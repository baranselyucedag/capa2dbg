#include "config.h"
#include "pluginmain.h"
#include "capa_cache.h"
#include "json.hpp"

#include <fstream>
#include <vector>
#include <string>
#include <cstring>

using json = nlohmann::json;

static std::vector<std::string> g_allowlist;
static std::string g_capaPath;
static bool g_labelCategoryPrefix = true;
static bool g_cacheEnabled = true;
static std::string g_cacheDir;
static int g_cacheMaxMb = 512;
static bool g_cacheAdoptManual = true;

static const char* kFallbackNamespaces[] = {
    "host-interaction/process",
    "host-interaction/thread",
    "host-interaction/registry",
    "data-manipulation",
    "persistence",
    "linking/runtime-linking",
    "collection",
    "host-interaction/clipboard",
    "anti-analysis",
    "communication",
    "c2",
};

static void UseFallback()
{
    g_allowlist.clear();
    for (const char* ns : kFallbackNamespaces)
        g_allowlist.emplace_back(ns);
    g_capaPath.clear();
    g_labelCategoryPrefix = true;
    g_cacheEnabled = true;
    g_cacheDir.clear();
    g_cacheMaxMb = 512;
    g_cacheAdoptManual = true;
}

static bool TryLoadFromPath(const char* path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return false;

    json j;
    try
    {
        f >> j;
    }
    catch (...)
    {
        return false;
    }

    if (!j.contains("breakpoint_namespaces") || !j["breakpoint_namespaces"].is_array())
        return false;

    g_allowlist.clear();
    for (auto& item : j["breakpoint_namespaces"])
    {
        if (item.is_string())
            g_allowlist.push_back(item.get<std::string>());
    }
    if (g_allowlist.empty())
        return false;

    g_capaPath.clear();
    if (j.contains("capa_path") && j["capa_path"].is_string())
        g_capaPath = j["capa_path"].get<std::string>();

    g_labelCategoryPrefix = true;
    if (j.contains("label_category_prefix") && j["label_category_prefix"].is_boolean())
        g_labelCategoryPrefix = j["label_category_prefix"].get<bool>();

    g_cacheEnabled = true;
    if (j.contains("cache_enabled") && j["cache_enabled"].is_boolean())
        g_cacheEnabled = j["cache_enabled"].get<bool>();

    g_cacheDir.clear();
    if (j.contains("cache_dir") && j["cache_dir"].is_string())
        g_cacheDir = j["cache_dir"].get<std::string>();

    g_cacheMaxMb = 512;
    if (j.contains("cache_max_mb") && j["cache_max_mb"].is_number_integer())
    {
        const int v = j["cache_max_mb"].get<int>();
        if (v > 0)
            g_cacheMaxMb = v;
    }

    g_cacheAdoptManual = true;
    if (j.contains("cache_adopt_manual") && j["cache_adopt_manual"].is_boolean())
        g_cacheAdoptManual = j["cache_adopt_manual"].get<bool>();

    return true;
}

static std::string GetPluginDirectory()
{
    HMODULE hMod = nullptr;
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&LoadAllowlistConfig),
            &hMod) ||
        !hMod)
    {
        return {};
    }

    char path[MAX_PATH] = {};
    DWORD n = GetModuleFileNameA(hMod, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return {};

    std::string full(path);
    size_t slash = full.find_last_of("\\/");
    if (slash == std::string::npos)
        return {};
    return full.substr(0, slash + 1);
}

static void LogCacheConfig()
{
    if (!g_cacheEnabled)
    {
        _plugin_logputs("[capa2dbg] cache: enabled=0");
        return;
    }

    const std::string dir = GetCacheDirDisplay();
    _plugin_logprintf("[capa2dbg] cache: enabled=1 dir=%s max=%dMB\n",
                      dir.empty() ? "(yazilabilir dizin yok)" : dir.c_str(),
                      g_cacheMaxMb);
}

void LoadAllowlistConfig()
{
    const std::string dir = GetPluginDirectory();
    const std::string candidates[] = {
        dir + "capa2dbg.json",
        dir + "config\\capa2dbg.json",
        dir + "..\\config\\capa2dbg.json",
        "config\\capa2dbg.json",
        "capa2dbg.json",
    };

    for (const auto& path : candidates)
    {
        if (TryLoadFromPath(path.c_str()))
        {
            _plugin_logprintf("[capa2dbg] Allowlist yuklendi: %s (%zu prefix)\n",
                              path.c_str(), g_allowlist.size());
            if (!g_capaPath.empty())
                _plugin_logprintf("[capa2dbg] capa_path=%s\n", g_capaPath.c_str());
            LogCacheConfig();
            return;
        }
    }

    UseFallback();
    _plugin_logprintf("[capa2dbg] Config bulunamadi, gomulu allowlist kullaniliyor (%zu prefix)\n",
                      g_allowlist.size());
    LogCacheConfig();
}

bool IsCriticalNamespace(const std::string& ns)
{
    if (ns.empty())
        return false;

    for (const auto& prefix : g_allowlist)
    {
        if (prefix.empty())
            continue;
        if (ns.size() >= prefix.size() && ns.compare(0, prefix.size(), prefix) == 0)
            return true;
    }
    return false;
}

std::string CapaCategory(const std::string& ns)
{
    struct Entry
    {
        const char* prefix;
        const char* cat;
    };
    static const Entry table[] = {
        {"host-interaction/process", "proc"},
        {"host-interaction/thread", "thread"},
        {"host-interaction/registry", "reg"},
        {"host-interaction/file-system", "fs"},
        {"host-interaction/clipboard", "clip"},
        {"host-interaction/gui", "gui"},
        {"host-interaction/environment-variable", "env"},
        {"host-interaction/os", "os"},
        {"host-interaction/hardware", "hw"},
        {"host-interaction/cli", "cli"},
        {"data-manipulation", "crypto"},
        {"persistence", "persist"},
        {"linking/runtime-linking", "dynimp"},
        {"collection", "collect"},
        {"communication", "net"},
        {"c2", "c2"},
        {"anti-analysis", "antidbg"},
        {"executable", "pkg"},
    };

    for (const auto& e : table)
    {
        const size_t len = std::strlen(e.prefix);
        if (ns.size() >= len && ns.compare(0, len, e.prefix) == 0)
            return e.cat;
    }
    return "misc";
}

std::string GetCapaPath()
{
    return g_capaPath;
}

bool LabelCategoryPrefixEnabled()
{
    return g_labelCategoryPrefix;
}

bool CacheEnabledConfig()
{
    return g_cacheEnabled;
}

std::string CacheDirOverride()
{
    return g_cacheDir;
}

int CacheMaxMb()
{
    return g_cacheMaxMb;
}

bool CacheAdoptManual()
{
    return g_cacheAdoptManual;
}
