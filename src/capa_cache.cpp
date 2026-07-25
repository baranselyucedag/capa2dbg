#include "capa_cache.h"
#include "pluginmain.h"
#include "config.h"
#include "json.hpp"

#include <bcrypt.h>

#include <algorithm>
#include <map>
#include <mutex>
#include <string>
#include <vector>

using json = nlohmann::json;

static std::mutex g_cacheMutex;

static const int kCacheSchema = 1;

// ---------------------------------------------------------------- utilities

static std::wstring AnsiToWide(const std::string& s)
{
    if (s.empty())
        return {};
    const int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0)
        return {};
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

static std::string WideToAnsi(const std::wstring& w)
{
    if (w.empty())
        return {};
    const int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), static_cast<int>(w.size()),
                                      nullptr, 0, nullptr, nullptr);
    if (n <= 0)
        return {};
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_ACP, 0, w.c_str(), static_cast<int>(w.size()), &s[0], n, nullptr, nullptr);
    return s;
}

static uint64_t FileTimeToU64(const FILETIME& ft)
{
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

static bool GetFileStampW(const std::wstring& path, uint64_t& sizeOut, uint64_t& mtimeOut)
{
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad))
        return false;

    ULARGE_INTEGER sz{};
    sz.LowPart = fad.nFileSizeLow;
    sz.HighPart = fad.nFileSizeHigh;
    sizeOut = sz.QuadPart;
    mtimeOut = FileTimeToU64(fad.ftLastWriteTime);
    return true;
}

static bool FileExistsW(const std::wstring& path)
{
    const DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static bool ReadWholeFileW(const std::wstring& path, std::string& out)
{
    out.clear();

    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0)
    {
        CloseHandle(h);
        return false;
    }

    out.resize(static_cast<size_t>(size.QuadPart));
    size_t done = 0;
    while (done < out.size())
    {
        const DWORD chunk = static_cast<DWORD>(
            (out.size() - done) > 0x100000 ? 0x100000 : (out.size() - done));
        DWORD read = 0;
        if (!ReadFile(h, &out[done], chunk, &read, nullptr) || read == 0)
        {
            CloseHandle(h);
            return false;
        }
        done += read;
    }

    CloseHandle(h);
    return true;
}

// Write to tmp_<pid>_<tick>_<n>.part then rename onto the final name.
static bool WriteFileAtomicW(const std::wstring& dir,
                             const std::wstring& finalName,
                             const std::string& data)
{
    static volatile LONG s_counter = 0;
    const LONG n = InterlockedIncrement(&s_counter);

    wchar_t tmpName[128] = {};
    swprintf_s(tmpName, L"tmp_%lu_%llu_%ld.part",
               GetCurrentProcessId(),
               static_cast<unsigned long long>(GetTickCount64()),
               n);

    const std::wstring tmpPath = dir + tmpName;
    const std::wstring finalPath = dir + finalName;

    HANDLE h = CreateFileW(tmpPath.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;

    size_t done = 0;
    while (done < data.size())
    {
        const DWORD chunk = static_cast<DWORD>(
            (data.size() - done) > 0x100000 ? 0x100000 : (data.size() - done));
        DWORD written = 0;
        if (!WriteFile(h, data.data() + done, chunk, &written, nullptr) || written == 0)
        {
            CloseHandle(h);
            DeleteFileW(tmpPath.c_str());
            return false;
        }
        done += written;
    }

    FlushFileBuffers(h);
    CloseHandle(h);

    if (!MoveFileExW(tmpPath.c_str(), finalPath.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        DeleteFileW(tmpPath.c_str());
        return false;
    }
    return true;
}

static void TouchFileW(const std::wstring& path)
{
    HANDLE h = CreateFileW(path.c_str(), FILE_WRITE_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return;

    SYSTEMTIME st{};
    GetSystemTime(&st);
    FILETIME ft{};
    if (SystemTimeToFileTime(&st, &ft))
        SetFileTime(h, nullptr, &ft, &ft);
    CloseHandle(h);
}

static std::string UtcNowIso8601()
{
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char buf[32] = {};
    sprintf_s(buf, "%04u-%02u-%02uT%02u:%02u:%02uZ",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// --------------------------------------------------------------- cache dir

static bool EnsureDirWritableW(const std::wstring& dir)
{
    if (dir.empty())
        return false;

    // Create the full chain (single level under an existing parent is typical).
    if (!CreateDirectoryW(dir.c_str(), nullptr))
    {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
            return false;
    }

    const std::wstring probe = dir + L".wtest";
    HANDLE h = CreateFileW(probe.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    CloseHandle(h);
    return true;
}

static std::wstring NormalizeDirW(std::wstring d)
{
    if (d.empty())
        return d;
    for (auto& c : d)
    {
        if (c == L'/')
            c = L'\\';
    }
    if (d.back() != L'\\')
        d.push_back(L'\\');
    return d;
}

static std::wstring PluginDirW()
{
    HMODULE hMod = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&GetCacheDirW),
            &hMod) ||
        !hMod)
    {
        return {};
    }

    wchar_t path[MAX_PATH] = {};
    const DWORD n = GetModuleFileNameW(hMod, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return {};

    std::wstring full(path);
    const size_t slash = full.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
        return {};
    return full.substr(0, slash + 1);
}

std::wstring GetCacheDirW()
{
    static std::wstring cached;
    static bool resolved = false;
    if (resolved)
        return cached;

    std::vector<std::wstring> candidates;

    const std::string cfg = CacheDirOverride();
    if (!cfg.empty())
        candidates.push_back(NormalizeDirW(AnsiToWide(cfg)));

    const std::wstring plugDir = PluginDirW();
    if (!plugDir.empty())
        candidates.push_back(plugDir + L"capa2dbg_cache\\");

    wchar_t localApp[MAX_PATH] = {};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", localApp, MAX_PATH) > 0)
    {
        std::wstring base = NormalizeDirW(localApp);
        // Create parent first so the leaf CreateDirectory can succeed.
        const std::wstring parent = base + L"capa2dbg\\";
        CreateDirectoryW(parent.c_str(), nullptr);
        candidates.push_back(parent + L"cache\\");
    }

    for (const auto& c : candidates)
    {
        if (EnsureDirWritableW(c))
        {
            cached = c;
            resolved = true;
            return cached;
        }
    }

    resolved = true;
    cached.clear();
    return cached;
}

std::string GetCacheDirDisplay()
{
    return WideToAnsi(GetCacheDirW());
}

// ------------------------------------------------------------------ sha256

static bool Sha256File(const std::wstring& path, std::string& hexOut)
{
    hexOut.clear();

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::vector<UCHAR> hashObj;
    std::vector<UCHAR> digest;
    bool ok = false;

    do
    {
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
            break;

        DWORD objLen = 0, hashLen = 0, cb = 0;
        if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                                              reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cb, 0)))
            break;
        if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                                              reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &cb, 0)))
            break;

        hashObj.resize(objLen);
        digest.resize(hashLen);

        if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObj.data(), objLen, nullptr, 0, 0)))
            break;

        std::vector<unsigned char> buf(0x100000); // 1 MB
        bool readOk = true;
        for (;;)
        {
            DWORD read = 0;
            if (!ReadFile(hFile, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr))
            {
                readOk = false;
                break;
            }
            if (read == 0)
                break;
            if (!BCRYPT_SUCCESS(BCryptHashData(hHash, buf.data(), read, 0)))
            {
                readOk = false;
                break;
            }
        }
        if (!readOk)
            break;

        if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, digest.data(), hashLen, 0)))
            break;

        static const char* kHex = "0123456789abcdef";
        hexOut.reserve(static_cast<size_t>(hashLen) * 2);
        for (DWORD i = 0; i < hashLen; ++i)
        {
            hexOut.push_back(kHex[(digest[i] >> 4) & 0xF]);
            hexOut.push_back(kHex[digest[i] & 0xF]);
        }
        ok = true;
    } while (false);

    if (hHash)
        BCryptDestroyHash(hHash);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);
    return ok;
}

bool ComputeFileSha256(const std::string& path, std::string& hexOut)
{
    hexOut.clear();
    if (path.empty())
        return false;

    const std::wstring wpath = AnsiToWide(path);
    if (wpath.empty())
        return false;

    uint64_t size = 0, mtime = 0;
    if (!GetFileStampW(wpath, size, mtime))
        return false;

    char keyBuf[64] = {};
    sprintf_s(keyBuf, "|%llu|%llu",
              static_cast<unsigned long long>(size),
              static_cast<unsigned long long>(mtime));

    std::string key = path;
    std::transform(key.begin(), key.end(), key.begin(),
                   [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    key += keyBuf;

    static std::mutex memoMutex;
    static std::map<std::string, std::string> memo;
    {
        std::lock_guard<std::mutex> lock(memoMutex);
        const auto it = memo.find(key);
        if (it != memo.end())
        {
            hexOut = it->second;
            return true;
        }
    }

    if (!Sha256File(wpath, hexOut))
        return false;

    {
        std::lock_guard<std::mutex> lock(memoMutex);
        memo[key] = hexOut;
    }
    return true;
}

// --------------------------------------------------------- lookup / store

static bool IsHex64(const std::wstring& s)
{
    if (s.size() != 64)
        return false;
    for (wchar_t c : s)
    {
        const bool hex = (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f');
        if (!hex)
            return false;
    }
    return true;
}

static void DeleteEntry(const std::wstring& dir, const std::string& sha)
{
    const std::wstring wsha = AnsiToWide(sha);
    DeleteFileW((dir + wsha + L".json").c_str());
    DeleteFileW((dir + wsha + L".meta.json").c_str());
}

bool CacheLookup(const std::string& sha, const std::string& capaExe, std::string& jsonOut)
{
    jsonOut.clear();
    if (sha.empty())
        return false;

    std::lock_guard<std::mutex> lock(g_cacheMutex);

    const std::wstring dir = GetCacheDirW();
    if (dir.empty())
        return false;

    const std::wstring wsha = AnsiToWide(sha);
    const std::wstring jsonPath = dir + wsha + L".json";
    const std::wstring metaPath = dir + wsha + L".meta.json";

    if (!FileExistsW(jsonPath) || !FileExistsW(metaPath))
        return false;

    std::string metaText;
    if (!ReadWholeFileW(metaPath, metaText))
        return false;

    json meta;
    try
    {
        meta = json::parse(metaText);
    }
    catch (...)
    {
        _plugin_logputs("[capa2dbg] cache STALE (meta bozuk) -> yeniden analiz");
        DeleteEntry(dir, sha);
        return false;
    }

    if (meta.value("schema", 0) != kCacheSchema)
    {
        _plugin_logputs("[capa2dbg] cache STALE (schema farkli) -> yeniden analiz");
        DeleteEntry(dir, sha);
        return false;
    }

    if (meta.value("target_sha256", std::string()) != sha)
    {
        _plugin_logputs("[capa2dbg] cache STALE (sha uyusmuyor) -> yeniden analiz");
        DeleteEntry(dir, sha);
        return false;
    }

    // Entries adopted from a manually loaded JSON have no capa.exe stamp.
    const std::string metaCapaExe = meta.value("capa_exe", std::string());
    if (!metaCapaExe.empty())
    {
        uint64_t curSize = 0, curMtime = 0;
        const std::wstring wcapa = AnsiToWide(capaExe);
        if (capaExe.empty() || !GetFileStampW(wcapa, curSize, curMtime))
        {
            // capa.exe unavailable: cannot validate, but cached data is still usable.
        }
        else
        {
            const uint64_t metaSize = meta.value("capa_exe_size", 0ULL);
            const uint64_t metaMtime = meta.value("capa_exe_mtime", 0ULL);
            if (metaSize != curSize || metaMtime != curMtime)
            {
                _plugin_logputs("[capa2dbg] cache STALE (capa.exe degisti) -> yeniden analiz");
                DeleteEntry(dir, sha);
                return false;
            }
        }
    }

    if (!ReadWholeFileW(jsonPath, jsonOut) || jsonOut.empty() || jsonOut[0] != '{')
    {
        _plugin_logputs("[capa2dbg] cache STALE (json bozuk) -> yeniden analiz");
        DeleteEntry(dir, sha);
        jsonOut.clear();
        return false;
    }

    TouchFileW(jsonPath);
    TouchFileW(metaPath);
    return true;
}

bool CacheStore(const std::string& sha,
                const std::string& targetPath,
                const std::string& capaExe,
                const std::string& capaVersion,
                const std::string& jsonText,
                const char* source)
{
    if (sha.empty() || jsonText.empty())
        return false;

    std::lock_guard<std::mutex> lock(g_cacheMutex);

    const std::wstring dir = GetCacheDirW();
    if (dir.empty())
    {
        _plugin_logputs("[capa2dbg] cache dizini yazilabilir degil, kaydedilmedi.");
        return false;
    }

    uint64_t targetSize = 0, targetMtime = 0;
    GetFileStampW(AnsiToWide(targetPath), targetSize, targetMtime);

    uint64_t capaSize = 0, capaMtime = 0;
    if (!capaExe.empty())
        GetFileStampW(AnsiToWide(capaExe), capaSize, capaMtime);

    json meta;
    meta["schema"] = kCacheSchema;
    meta["target_path"] = targetPath;
    meta["target_size"] = targetSize;
    meta["target_mtime"] = targetMtime;
    meta["target_sha256"] = sha;
    meta["capa_exe"] = capaExe;
    meta["capa_exe_size"] = capaSize;
    meta["capa_exe_mtime"] = capaMtime;
    meta["capa_version"] = capaVersion;
    meta["json_size"] = jsonText.size();
    meta["created_utc"] = UtcNowIso8601();
    meta["plugin_version"] = PLUGIN_VERSION;
    meta["source"] = source ? source : "";

    const std::wstring wsha = AnsiToWide(sha);

    // JSON first, meta last: an entry without meta is never treated as a hit.
    if (!WriteFileAtomicW(dir, wsha + L".json", jsonText))
        return false;
    if (!WriteFileAtomicW(dir, wsha + L".meta.json", meta.dump(2)))
    {
        DeleteFileW((dir + wsha + L".json").c_str());
        return false;
    }
    return true;
}

// ------------------------------------------------------------ maintenance

struct EntryStat
{
    std::wstring sha;
    uint64_t bytes = 0;
    uint64_t mtime = 0;
};

static std::vector<EntryStat> EnumEntries(const std::wstring& dir)
{
    std::vector<EntryStat> out;
    if (dir.empty())
        return out;

    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((dir + L"*.json").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return out;

    do
    {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        std::wstring name(fd.cFileName);
        const std::wstring suffix = L".json";
        if (name.size() <= suffix.size())
            continue;
        if (name.size() >= 10 && name.compare(name.size() - 10, 10, L".meta.json") == 0)
            continue;

        const std::wstring stem = name.substr(0, name.size() - suffix.size());
        if (!IsHex64(stem))
            continue;

        EntryStat es;
        es.sha = stem;
        ULARGE_INTEGER sz{};
        sz.LowPart = fd.nFileSizeLow;
        sz.HighPart = fd.nFileSizeHigh;
        es.bytes = sz.QuadPart;
        es.mtime = FileTimeToU64(fd.ftLastWriteTime);

        uint64_t metaSize = 0, metaMtime = 0;
        if (GetFileStampW(dir + stem + L".meta.json", metaSize, metaMtime))
            es.bytes += metaSize;

        out.push_back(std::move(es));
    } while (FindNextFileW(h, &fd));

    FindClose(h);
    return out;
}

size_t CacheClear()
{
    std::lock_guard<std::mutex> lock(g_cacheMutex);

    const std::wstring dir = GetCacheDirW();
    if (dir.empty())
        return 0;

    const auto entries = EnumEntries(dir);
    for (const auto& e : entries)
    {
        DeleteFileW((dir + e.sha + L".json").c_str());
        DeleteFileW((dir + e.sha + L".meta.json").c_str());
    }
    return entries.size();
}

void CacheInfoToLog()
{
    std::lock_guard<std::mutex> lock(g_cacheMutex);

    const std::wstring dir = GetCacheDirW();
    if (dir.empty())
    {
        _plugin_logputs("[capa2dbg] cache: yazilabilir dizin yok (devre disi).");
        return;
    }

    const auto entries = EnumEntries(dir);
    uint64_t total = 0;
    for (const auto& e : entries)
        total += e.bytes;

    _plugin_logprintf("[capa2dbg] cache: %zu entry, %.2f MB, dir=%s\n",
                      entries.size(),
                      static_cast<double>(total) / (1024.0 * 1024.0),
                      WideToAnsi(dir).c_str());
}

void PruneCache(int maxMb)
{
    if (maxMb <= 0)
        return;

    std::lock_guard<std::mutex> lock(g_cacheMutex);

    const std::wstring dir = GetCacheDirW();
    if (dir.empty())
        return;

    auto entries = EnumEntries(dir);
    uint64_t total = 0;
    for (const auto& e : entries)
        total += e.bytes;

    const uint64_t limit = static_cast<uint64_t>(maxMb) * 1024ULL * 1024ULL;
    if (total <= limit)
        return;

    std::sort(entries.begin(), entries.end(),
              [](const EntryStat& a, const EntryStat& b) { return a.mtime < b.mtime; });

    size_t removed = 0;
    for (const auto& e : entries)
    {
        if (total <= limit)
            break;
        DeleteFileW((dir + e.sha + L".json").c_str());
        DeleteFileW((dir + e.sha + L".meta.json").c_str());
        total = (total > e.bytes) ? (total - e.bytes) : 0;
        ++removed;
    }

    if (removed)
    {
        _plugin_logprintf("[capa2dbg] cache budandi: %zu entry silindi (limit %d MB).\n",
                          removed, maxMb);
    }
}
