#pragma once

#include <string>
#include <unordered_map>

struct ApiFmt
{
    const char* argFmt;
};

// x86 stdcall: [esp]=retaddr, [esp+4]=arg1, [esp+8]=arg2, ...
inline const std::unordered_map<std::string, ApiFmt>& ApiTable()
{
    static const std::unordered_map<std::string, ApiFmt> t = {
        {"CreateProcessW", {"cmd={utf16@[esp+8]}"}},
        {"CreateProcessA", {"cmd={ascii@[esp+8]}"}},
        {"ShellExecuteW", {"file={utf16@[esp+c]} params={utf16@[esp+10]}"}},
        {"ShellExecuteA", {"file={ascii@[esp+c]} params={ascii@[esp+10]}"}},
        {"CreateFileW", {"name={utf16@[esp+4]}"}},
        {"CreateFileA", {"name={ascii@[esp+4]}"}},
        {"WriteFile", {"h={x:[esp+4]} len={d:[esp+c]}"}},
        {"ReadFile", {"h={x:[esp+4]} len={d:[esp+c]}"}},
        {"RegSetValueExW", {"val={utf16@[esp+8]}"}},
        {"RegSetValueExA", {"val={ascii@[esp+8]}"}},
        {"RegCreateKeyExW", {"sub={utf16@[esp+8]}"}},
        {"RegCreateKeyExA", {"sub={ascii@[esp+8]}"}},
        {"RegOpenKeyExW", {"sub={utf16@[esp+8]}"}},
        {"RegOpenKeyExA", {"sub={ascii@[esp+8]}"}},
        {"RegDeleteKeyW", {"sub={utf16@[esp+8]}"}},
        {"RegDeleteValueW", {"val={utf16@[esp+8]}"}},
        {"CreateThread", {"start={x:[esp+c]}"}},
        {"CreateRemoteThread", {"proc={x:[esp+4]} start={x:[esp+10]}"}},
        {"VirtualAlloc", {"addr={x:[esp+4]} size={d:[esp+8]}"}},
        {"VirtualAllocEx", {"proc={x:[esp+4]} size={d:[esp+c]}"}},
        {"VirtualProtect", {"addr={x:[esp+4]} size={d:[esp+8]}"}},
        {"LoadLibraryW", {"lib={utf16@[esp+4]}"}},
        {"LoadLibraryA", {"lib={ascii@[esp+4]}"}},
        {"LoadLibraryExW", {"lib={utf16@[esp+4]}"}},
        {"GetProcAddress", {"name={ascii@[esp+8]}"}},
        {"CopyFileW", {"src={utf16@[esp+4]} dst={utf16@[esp+8]}"}},
        {"CopyFileA", {"src={ascii@[esp+4]} dst={ascii@[esp+8]}"}},
        {"MoveFileW", {"src={utf16@[esp+4]} dst={utf16@[esp+8]}"}},
        {"MoveFileA", {"src={ascii@[esp+4]} dst={ascii@[esp+8]}"}},
        {"DeleteFileW", {"file={utf16@[esp+4]}"}},
        {"DeleteFileA", {"file={ascii@[esp+4]}"}},
        {"WinExec", {"cmd={ascii@[esp+4]}"}},
        {"SetFileAttributesW", {"file={utf16@[esp+4]} attr={x:[esp+8]}"}},
        {"WriteProcessMemory", {"proc={x:[esp+4]} addr={x:[esp+8]} size={d:[esp+10]}"}},
        {"ReadProcessMemory", {"proc={x:[esp+4]} addr={x:[esp+8]} size={d:[esp+10]}"}},
        {"OpenProcess", {"access={x:[esp+4]} pid={d:[esp+c]}"}},
        {"URLDownloadToFileW", {"url={utf16@[esp+8]} file={utf16@[esp+c]}"}},
        {"InternetOpenUrlW", {"url={utf16@[esp+8]}"}},
        {"HttpSendRequestW", {"headers={utf16@[esp+8]}"}},
    };
    return t;
}

inline const char* GenericApiFmt()
{
    return "arg1={x:[esp+4]} arg2={x:[esp+8]} arg3={x:[esp+c]}";
}

// Strip module prefix: "kernel32.CreateProcessW" -> "CreateProcessW"
inline std::string StripApiLabel(const std::string& label)
{
    const size_t dot = label.find_last_of('.');
    if (dot != std::string::npos && dot + 1 < label.size())
        return label.substr(dot + 1);
    return label;
}
