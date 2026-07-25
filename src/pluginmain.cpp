#include "pluginmain.h"
#include "capa_loader.h"
#include "applier.h"
#include "config.h"
#include "capa_runner.h"
#include "capa_cache.h"

#include <commdlg.h>
#include <cstring>
#include <fstream>
#include <sstream>
#include <thread>
#include <string>

int g_pluginHandle = 0;
HWND g_hwndDlg = nullptr;
int g_hMenu = 0;

static bool g_bpCriticalOnly = true;    // default: critical namespaces only
static bool g_cacheEnabledSession = true; // seeded from config, toggled from the menu

static void StartCapaRunAsync(bool force)
{
    if (!DbgIsDebugging())
    {
        _plugin_logputs("[capa2dbg] Once hedefi yukle.");
        return;
    }

    const std::string capaExe = GetCapaPath();
    if (capaExe.empty())
    {
        _plugin_logputs("[capa2dbg] config'te capa_path yok; JSON sec / capa_load kullan.");
        return;
    }

    std::string target;
    if (!GetDebuggedTargetPath(target))
    {
        _plugin_logputs("[capa2dbg] Hedef yolu alinamadi.");
        return;
    }
    if (!TargetFileExists(target))
    {
        _plugin_logprintf("[capa2dbg] Hedef dosya diskte bulunamadi: %s\n", target.c_str());
        return;
    }

    const bool useCache = g_cacheEnabledSession && !force;
    const bool criticalOnly = g_bpCriticalOnly;

    std::thread([capaExe, target, useCache, criticalOnly]() {
        std::string sha;
        const bool haveSha = ComputeFileSha256(target, sha);
        if (!haveSha && g_cacheEnabledSession)
            _plugin_logputs("[capa2dbg] SHA256 hesaplanamadi, cache atlaniyor.");

        std::string js;
        bool fromCache = false;

        if (useCache && haveSha && CacheLookup(sha, capaExe, js))
        {
            fromCache = true;
            _plugin_logprintf("[capa2dbg] cache HIT sha=%.12s... (%zu byte)\n",
                              sha.c_str(), js.size());
        }
        else
        {
            if (useCache && haveSha)
                _plugin_logprintf("[capa2dbg] cache MISS sha=%.12s... -> capa calisiyor\n",
                                  sha.c_str());
            else
                _plugin_logputs("[capa2dbg] capa calisiyor... (cache devre disi)");

            if (!RunCapaOnTarget(capaExe, target, js))
            {
                _plugin_logputs("[capa2dbg] capa calistirma basarisiz.");
                return;
            }
        }

        CapaResult res;
        if (!LoadCapaJsonFromString(js, res))
        {
            // Never cache output that does not parse.
            _plugin_logputs("[capa2dbg] capa ciktisi parse edilemedi.");
            return;
        }

        if (!fromCache && haveSha && g_cacheEnabledSession)
        {
            if (CacheStore(sha, target, capaExe, res.capaVersion, js, "capa_run"))
            {
                _plugin_logprintf("[capa2dbg] cache STORE sha=%.12s... (%zu byte, capa %s)\n",
                                  sha.c_str(), js.size(),
                                  res.capaVersion.empty() ? "?" : res.capaVersion.c_str());
                PruneCache(CacheMaxMb());
            }
        }

        ApplyCapa(res, criticalOnly);
    }).detach();
}

// Store a manually supplied JSON under the target's hash so the next capa_run hits.
static void AdoptJsonIntoCache(const std::string& jsonText, const CapaResult& res)
{
    if (jsonText.empty() || !g_cacheEnabledSession || !CacheAdoptManual())
        return;

    std::string target;
    if (!GetDebuggedTargetPath(target) || !TargetFileExists(target))
        return;

    std::string sha;
    if (!ComputeFileSha256(target, sha))
        return;

    // Do not downgrade an entry that capa_run already validated against capa.exe.
    std::string existing;
    if (CacheLookup(sha, GetCapaPath(), existing))
        return;

    if (CacheStore(sha, target, std::string(), res.capaVersion, jsonText, "capa_load_adopted"))
    {
        _plugin_logprintf("[capa2dbg] cache ADOPT sha=%.12s... (%zu byte)\n",
                          sha.c_str(), jsonText.size());
        PruneCache(CacheMaxMb());
    }
}

static bool ApplyFromJsonFile(const char* path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return false;

    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string text = ss.str();

    CapaResult res;
    if (!LoadCapaJsonFromString(text, res))
        return false;

    ApplyCapa(res, g_bpCriticalOnly);
    AdoptJsonIntoCache(text, res);
    return true;
}

static bool cbCapaLoad(int argc, char** argv)
{
    if (!DbgIsDebugging())
    {
        _plugin_logputs("[capa2dbg] Once hedef binary'yi yukle/calistir.");
        return false;
    }
    if (argc < 2)
    {
        _plugin_logputs("[capa2dbg] Kullanim: capa_load <malware.json>");
        return false;
    }

    if (!ApplyFromJsonFile(argv[1]))
    {
        _plugin_logprintf("[capa2dbg] JSON okunamadi: %s\n", argv[1]);
        return false;
    }
    return true;
}

static bool cbCapaRun(int argc, char** argv)
{
    const bool force = (argc >= 2 && argv[1] &&
                        (!_stricmp(argv[1], "force") || !_stricmp(argv[1], "-f")));
    StartCapaRunAsync(force);
    return true;
}

static bool cbCacheInfo(int /*argc*/, char** /*argv*/)
{
    CacheInfoToLog();
    return true;
}

static bool cbCacheClear(int /*argc*/, char** /*argv*/)
{
    const size_t n = CacheClear();
    _plugin_logprintf("[capa2dbg] cache temizlendi: %zu entry silindi.\n", n);
    return true;
}

static void doLoadDialog()
{
    if (!DbgIsDebugging())
    {
        _plugin_logputs("[capa2dbg] Once hedefi yukle.");
        return;
    }

    char path[MAX_PATH] = {};
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwndDlg;
    ofn.lpstrFilter = "capa JSON\0*.json\0Tum dosyalar\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;

    if (!GetOpenFileNameA(&ofn))
        return;

    if (!ApplyFromJsonFile(path))
        _plugin_logprintf("[capa2dbg] JSON okunamadi: %s\n", path);
}

static void cbMenuEntry(CBTYPE /*cbType*/, void* callbackInfo)
{
    auto* info = static_cast<PLUG_CB_MENUENTRY*>(callbackInfo);
    switch (info->hEntry)
    {
    case MENU_LOAD:
        doLoadDialog();
        break;
    case MENU_RUN_CAPA:
        StartCapaRunAsync(false);
        break;
    case MENU_RUN_CAPA_FORCE:
        StartCapaRunAsync(true);
        break;
    case MENU_TOGGLE_BP:
        g_bpCriticalOnly = !g_bpCriticalOnly;
        _plugin_logprintf("[capa2dbg] Breakpoint modu: %s\n",
                          g_bpCriticalOnly ? "sadece KRITIK" : "TUMU");
        break;
    case MENU_TOGGLE_ARGLOG:
        g_argLogging = !g_argLogging;
        _plugin_logprintf("[capa2dbg] Arg logging: %s\n", g_argLogging ? "ON" : "OFF");
        break;
    case MENU_TOGGLE_SILENT:
        g_bpSilent = !g_bpSilent;
        _plugin_logprintf("[capa2dbg] Log BP: %s\n", g_bpSilent ? "SILENT (durmaz)" : "BREAK (durur)");
        break;
    case MENU_TOGGLE_CACHE:
        g_cacheEnabledSession = !g_cacheEnabledSession;
        _plugin_logprintf("[capa2dbg] cache: %s\n", g_cacheEnabledSession ? "ON" : "OFF");
        break;
    case MENU_CACHE_INFO:
        CacheInfoToLog();
        break;
    case MENU_CACHE_CLEAR:
    {
        const size_t n = CacheClear();
        _plugin_logprintf("[capa2dbg] cache temizlendi: %zu entry silindi.\n", n);
        break;
    }
    case MENU_CLEAR:
        ClearCapaMarks();
        break;
    case MENU_SUMMARY:
        PrintLastSummary();
        break;
    default:
        break;
    }
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(initStruct->pluginName, PLUGIN_NAME);

    g_pluginHandle = initStruct->pluginHandle;

    _plugin_registercommand(g_pluginHandle, "capa_load", cbCapaLoad, false);
    _plugin_registercommand(g_pluginHandle, "capa_run", cbCapaRun, false);
    _plugin_registercommand(g_pluginHandle, "capa_cache_info", cbCacheInfo, false);
    _plugin_registercommand(g_pluginHandle, "capa_cache_clear", cbCacheClear, false);

    LoadAllowlistConfig();
    g_cacheEnabledSession = CacheEnabledConfig();

    _plugin_logputs("[capa2dbg] yuklendi. Komutlar: capa_load <json> | capa_run [force] | "
                    "capa_cache_info | capa_cache_clear");
    return true;
}

extern "C" __declspec(dllexport) bool plugstop()
{
    _plugin_unregistercommand(g_pluginHandle, "capa_load");
    _plugin_unregistercommand(g_pluginHandle, "capa_run");
    _plugin_unregistercommand(g_pluginHandle, "capa_cache_info");
    _plugin_unregistercommand(g_pluginHandle, "capa_cache_clear");
    _plugin_unregistercallback(g_pluginHandle, CB_MENUENTRY);
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    g_hwndDlg = setupStruct->hwndDlg;
    g_hMenu = setupStruct->hMenu;

    _plugin_menuaddentry(g_hMenu, MENU_LOAD, "Load capa JSON & Apply");
    _plugin_menuaddentry(g_hMenu, MENU_RUN_CAPA, "Run capa on current target");
    _plugin_menuaddentry(g_hMenu, MENU_RUN_CAPA_FORCE, "Run capa (force, ignore cache)");
    _plugin_menuaddentry(g_hMenu, MENU_TOGGLE_BP, "Toggle breakpoints: Critical / All");
    _plugin_menuaddentry(g_hMenu, MENU_TOGGLE_ARGLOG, "Toggle arg logging: On / Off");
    _plugin_menuaddentry(g_hMenu, MENU_TOGGLE_SILENT, "Toggle log BP: Silent / Break");
    _plugin_menuaddentry(g_hMenu, MENU_TOGGLE_CACHE, "Toggle cache: On / Off");
    _plugin_menuaddentry(g_hMenu, MENU_CACHE_INFO, "Cache: show info");
    _plugin_menuaddentry(g_hMenu, MENU_CACHE_CLEAR, "Cache: clear all");
    _plugin_menuaddentry(g_hMenu, MENU_CLEAR, "Clear all capa marks (undo)");
    _plugin_menuaddentry(g_hMenu, MENU_SUMMARY, "Show last summary in log");
    _plugin_registercallback(g_pluginHandle, CB_MENUENTRY, cbMenuEntry);
}
