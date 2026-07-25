#pragma once

#include <string>

// Cache directory (created on demand). Empty if no writable location found.
std::wstring GetCacheDirW();
std::string GetCacheDirDisplay();

// Lowercase hex SHA256 of a file. Reads in 1 MB chunks via CNG.
// Results are memoized per (path, size, mtime) for the session.
bool ComputeFileSha256(const std::string& path, std::string& hexOut);

// Returns true on HIT (jsonOut filled). Stale/corrupt pairs are deleted.
// An entry stored with an empty capaExe (adopted manual JSON) is always accepted.
bool CacheLookup(const std::string& sha, const std::string& capaExe, std::string& jsonOut);

// Only call after the JSON parsed successfully. Writes atomically.
bool CacheStore(const std::string& sha,
                const std::string& targetPath,
                const std::string& capaExe,
                const std::string& capaVersion,
                const std::string& json,
                const char* source);

size_t CacheClear();
void CacheInfoToLog();
void PruneCache(int maxMb);
