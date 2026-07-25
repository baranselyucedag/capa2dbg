#pragma once

#include <string>

// Disk path of the debugged main module (ANSI, from x64dbg).
bool GetDebuggedTargetPath(std::string& out);

// Wide existence check for the target file.
bool TargetFileExists(const std::string& path);

// Run capa.exe -j -vv against targetPath.
// Blocks until capa exits; call from a worker thread.
bool RunCapaOnTarget(const std::string& capaExe,
                     const std::string& targetPath,
                     std::string& jsonOut);
