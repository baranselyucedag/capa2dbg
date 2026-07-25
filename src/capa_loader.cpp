#include "capa_loader.h"
#include "pluginmain.h"
#include "json.hpp"

#include <fstream>
#include <sstream>
#include <string>

using json = nlohmann::json;

static CapaScope ParseScope(const std::string& s)
{
    if (s == "instruction")
        return CapaScope::Instruction;
    if (s == "basic block")
        return CapaScope::BasicBlock;
    if (s == "function")
        return CapaScope::Function;
    if (s == "file")
        return CapaScope::File;
    return CapaScope::Unknown;
}

bool LoadCapaJsonFromString(const std::string& text, CapaResult& out)
{
    out = CapaResult{};

    json j;
    try
    {
        j = json::parse(text);
    }
    catch (const std::exception& ex)
    {
        _plugin_logprintf("[capa2dbg] JSON parse hatasi: %s\n", ex.what());
        return false;
    }
    catch (...)
    {
        _plugin_logputs("[capa2dbg] JSON parse hatasi (bilinmeyen)");
        return false;
    }

    if (!j.contains("meta") || !j["meta"].contains("analysis"))
    {
        _plugin_logputs("[capa2dbg] meta.analysis bulunamadi (capa -j / -vv bekleniyor)");
        return false;
    }

    auto& analysis = j["meta"]["analysis"];
    if (!analysis.contains("base_address") || !analysis["base_address"].contains("value"))
    {
        _plugin_logputs("[capa2dbg] base_address.value bulunamadi");
        return false;
    }

    out.baseValue = analysis["base_address"]["value"].get<uint64_t>();
    out.arch = analysis.value("arch", "");
    out.capaVersion = j["meta"].value("version", "");

    if (out.arch != "i386")
    {
        _plugin_logprintf("[capa2dbg] UYARI: arch=%s (x32 plugin i386 bekler)\n",
                          out.arch.empty() ? "(bos)" : out.arch.c_str());
    }

    if (analysis.contains("layout") && analysis["layout"].contains("functions"))
    {
        for (auto& fn : analysis["layout"]["functions"])
        {
            if (!fn.contains("address"))
                continue;
            auto& a = fn["address"];
            if (a.value("type", "") == "absolute" && a.contains("value"))
                out.functionStarts.push_back(a["value"].get<uint64_t>());
        }
    }

    if (!j.contains("rules") || !j["rules"].is_object())
    {
        _plugin_logputs("[capa2dbg] rules objesi bulunamadi");
        return false;
    }

    for (auto it = j["rules"].begin(); it != j["rules"].end(); ++it)
    {
        const auto& rule = it.value();
        if (!rule.contains("meta") || !rule.contains("matches"))
            continue;

        const auto& meta = rule["meta"];
        std::string name = meta.value("name", it.key());

        std::string ns;
        if (meta.contains("namespace") && !meta["namespace"].is_null())
            ns = meta["namespace"].get<std::string>();

        bool isLib = meta.value("lib", false);

        std::string scopeStr;
        if (meta.contains("scopes") && meta["scopes"].is_object())
            scopeStr = meta["scopes"].value("static", "");
        CapaScope scope = ParseScope(scopeStr);

        if (!rule["matches"].is_array())
            continue;

        for (auto& m : rule["matches"])
        {
            if (!m.is_array() || m.empty())
                continue;

            auto& addr = m[0];
            if (!addr.is_object())
                continue;

            const std::string atype = addr.value("type", "");
            if (atype == "absolute" && addr.contains("value"))
            {
                CapaMatch cm;
                cm.ruleName = name;
                cm.ns = ns;
                cm.scope = scope;
                cm.isLib = isLib;
                cm.hasAddr = true;
                cm.va = addr["value"].get<uint64_t>();
                out.matches.push_back(std::move(cm));
            }
            else
            {
                std::string note = name;
                if (!ns.empty())
                    note += " [" + ns + "]";
                out.fileScopeNotes.push_back(std::move(note));
            }
        }
    }

    _plugin_logprintf(
        "[capa2dbg] JSON okundu: base=0x%llX arch=%s funcs=%zu matches=%zu file-scope=%zu\n",
        static_cast<unsigned long long>(out.baseValue),
        out.arch.c_str(),
        out.functionStarts.size(),
        out.matches.size(),
        out.fileScopeNotes.size());

    return true;
}

bool LoadCapaJson(const char* path, CapaResult& out)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return false;

    std::ostringstream ss;
    ss << f.rdbuf();
    return LoadCapaJsonFromString(ss.str(), out);
}
