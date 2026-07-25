#pragma once

#include <string>
#include <vector>
#include <cstdint>

enum class CapaScope
{
    Instruction,
    BasicBlock,
    Function,
    File,
    Unknown
};

struct CapaMatch
{
    std::string ruleName;
    std::string ns; // namespace (empty if absent)
    CapaScope scope = CapaScope::Unknown;
    bool isLib = false;
    bool hasAddr = false;
    uint64_t va = 0; // capa absolute VA (preferred base)
};

struct CapaResult
{
    uint64_t baseValue = 0; // meta.analysis.base_address.value
    std::string arch;       // e.g. "i386"
    std::string capaVersion; // meta.version, e.g. "9.4.0"
    std::vector<CapaMatch> matches;
    std::vector<uint64_t> functionStarts; // layout.functions[].address (VA)
    std::vector<std::string> fileScopeNotes;
};
