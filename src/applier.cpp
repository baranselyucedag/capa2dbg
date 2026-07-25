#include "applier.h"
#include "pluginmain.h"
#include "config.h"
#include "api_table.h"

#include <map>
#include <set>
#include <string>
#include <vector>
#include <cctype>
#include <cstdio>
#include <algorithm>
#include <cstring>

#include "_dbgfunctions.h"

bool g_argLogging = true;
bool g_bpSilent = true;

struct Aggregated
{
    std::set<std::string> rules;
    bool funcScope = false;
    bool critical = false;
    std::string ns;
};

struct Touched
{
    duint addr = 0;
    bool hasBp = false;
    bool hasLabel = false;
    bool hasAutoComment = false;
    bool hasComment = false;
    bool hasBookmark = false;
};

static std::vector<Touched> g_touched;
static std::string g_lastSummary;

static duint Rebase(uint64_t capaVa, uint64_t baseValue)
{
    const duint runtimeBase = Script::Module::GetMainModuleBase();
    return static_cast<duint>(runtimeBase + (capaVa - baseValue));
}

static std::string SanitizeRuleName(std::string s)
{
    for (char& c : s)
    {
        if (!std::isalnum(static_cast<unsigned char>(c)))
            c = '_';
    }
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static bool ResolveCallApi(duint addr, std::string& apiOut, duint& retAddrOut)
{
    DISASM_INSTR instr = {};
    DbgDisasmAt(addr, &instr);
    if (instr.instr_size <= 0)
        return false;

    retAddrOut = addr + static_cast<duint>(instr.instr_size);

    if (_strnicmp(instr.instruction, "call", 4) != 0)
        return false;

    duint target = 0;
    if (instr.argcount >= 1 && instr.arg[0].memvalue)
        target = instr.arg[0].memvalue;
    else if (instr.argcount >= 1)
        target = instr.arg[0].value;

    if (!target)
        return false;

    char label[MAX_LABEL_SIZE] = {};
    if (!DbgGetLabelAt(target, SEG_DEFAULT, label) || !label[0])
        return false;

    apiOut = StripApiLabel(label);
    return !apiOut.empty();
}

static void SetLogBreakpoint(duint addr, const std::string& logText, bool silent)
{
    Script::Debug::SetBreakpoint(addr);

    BP_REF ref{};
    if (!DbgFunctions()->BpRefVa(&ref, bp_normal, addr))
        return;

    ref.SetField(bpf_logtext, logText);
    ref.SetField(bpf_logcondition, std::string("1"));
    ref.SetField(bpf_breakcondition, std::string(silent ? "0" : "1"));
    ref.SetField(bpf_fastresume, static_cast<duint>(silent ? 1 : 0));
}

void ApplyCapa(const CapaResult& res, bool bpCriticalOnly)
{
    std::set<uint64_t> funcSet(res.functionStarts.begin(), res.functionStarts.end());
    std::map<duint, Aggregated> byAddr;

    for (const auto& m : res.matches)
    {
        if (!m.hasAddr)
            continue;

        const duint real = Rebase(m.va, res.baseValue);
        Aggregated& agg = byAddr[real];
        agg.rules.insert(m.ruleName);

        if (m.scope == CapaScope::Function && funcSet.count(m.va) != 0)
            agg.funcScope = true;

        if (!m.isLib && IsCriticalNamespace(m.ns))
            agg.critical = true;

        // Prefer critical namespace as representative; else first non-empty
        if (agg.ns.empty())
            agg.ns = m.ns;
        else if (!m.isLib && IsCriticalNamespace(m.ns) && !IsCriticalNamespace(agg.ns))
            agg.ns = m.ns;
    }

    size_t nComment = 0;
    size_t nLabel = 0;
    size_t nBookmark = 0;
    size_t nBp = 0;
    size_t nLogBp = 0;
    size_t nFuncSummary = 0;

    if (!g_touched.empty())
        ClearCapaMarks();

    for (auto& kv : byAddr)
    {
        const duint addr = kv.first;
        Aggregated& agg = kv.second;

        std::string txt = "[capa] ";
        bool first = true;
        for (const auto& r : agg.rules)
        {
            if (!first)
                txt += " | ";
            txt += r;
            first = false;
        }

        Script::Comment::Set(addr, txt.c_str());
        ++nComment;

        Script::Bookmark::Set(addr);
        ++nBookmark;

        Touched t{};
        t.addr = addr;
        t.hasComment = true;
        t.hasBookmark = true;

        if (agg.funcScope && !agg.rules.empty())
        {
            std::string base = SanitizeRuleName(*agg.rules.begin());
            std::string lbl;
            if (LabelCategoryPrefixEnabled())
            {
                const std::string cat = CapaCategory(agg.ns);
                lbl = "capa_" + cat + "_" + base;
            }
            else
            {
                lbl = "capa_" + base;
            }
            Script::Label::Set(addr, lbl.c_str(), false, false);
            ++nLabel;
            t.hasLabel = true;
        }

        if (!bpCriticalOnly || agg.critical)
        {
            bool usedLogBp = false;
            if (g_argLogging)
            {
                std::string api;
                duint retAddr = 0;
                if (ResolveCallApi(addr, api, retAddr))
                {
                    const auto it = ApiTable().find(api);
                    const char* argFmt = (it != ApiTable().end()) ? it->second.argFmt : GenericApiFmt();

                    SetLogBreakpoint(addr, "[capa] " + api + " " + argFmt, g_bpSilent);
                    SetLogBreakpoint(retAddr, "[capa] " + api + " -> ret={x:eax}", g_bpSilent);

                    t.hasBp = true;
                    Touched retTouched{};
                    retTouched.addr = retAddr;
                    retTouched.hasBp = true;
                    g_touched.push_back(retTouched);
                    ++nBp;
                    nLogBp += 2;
                    usedLogBp = true;
                }
            }

            if (!usedLogBp)
            {
                Script::Debug::SetBreakpoint(addr);
                t.hasBp = true;
                ++nBp;
            }
        }

        g_touched.push_back(t);
    }

    // Feature 2: function-level capability summaries
    std::map<duint, std::set<std::string>> byFunc;
    for (const auto& m : res.matches)
    {
        if (!m.hasAddr)
            continue;
        const duint real = Rebase(m.va, res.baseValue);
        duint fnStart = 0;
        duint fnEnd = 0;
        if (DbgFunctionGet(real, &fnStart, &fnEnd))
            byFunc[fnStart].insert(m.ruleName);
    }

    for (const auto& kv : byFunc)
    {
        const duint fnStart = kv.first;
        if (kv.second.size() < 2)
            continue;

        std::string sum = "capa_fn: ";
        bool first = true;
        for (const auto& r : kv.second)
        {
            if (!first)
                sum += " | ";
            sum += r;
            first = false;
        }

        DbgSetAutoCommentAt(fnStart, sum.c_str());
        Touched ft{};
        ft.addr = fnStart;
        ft.hasAutoComment = true;
        g_touched.push_back(ft);
        ++nFuncSummary;
    }

    for (const auto& note : res.fileScopeNotes)
        _plugin_logprintf("[capa2dbg] (file-scope, adres yok) %s\n", note.c_str());

    char buf[420] = {};
    sprintf_s(buf,
              "[capa2dbg] Ozet: %zu adres | %zu yorum | %zu label | %zu bookmark | %zu bp "
              "(%zu log-bp pair/sites) | %zu fn-ozet (%s, arglog=%s, silent=%s)",
              byAddr.size(), nComment, nLabel, nBookmark, nBp, nLogBp, nFuncSummary,
              bpCriticalOnly ? "kritik" : "tumu",
              g_argLogging ? "on" : "off",
              g_bpSilent ? "on" : "off");
    g_lastSummary = buf;
    _plugin_logputs(buf);
    GuiUpdateAllViews();
}

void ClearCapaMarks()
{
    for (const auto& t : g_touched)
    {
        if (t.hasComment)
            Script::Comment::Delete(t.addr);
        if (t.hasBookmark)
            Script::Bookmark::Delete(t.addr);
        if (t.hasLabel)
            Script::Label::Delete(t.addr);
        if (t.hasBp)
            Script::Debug::DeleteBreakpoint(t.addr);
        if (t.hasAutoComment)
            DbgSetAutoCommentAt(t.addr, "");
    }
    _plugin_logprintf("[capa2dbg] %zu adresteki capa isaretleri temizlendi.\n", g_touched.size());
    g_touched.clear();
    GuiUpdateAllViews();
}

void PrintLastSummary()
{
    if (g_lastSummary.empty())
        _plugin_logputs("[capa2dbg] Henuz uygulama yapilmadi.");
    else
        _plugin_logputs(g_lastSummary.c_str());
}
