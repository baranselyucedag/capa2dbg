#include "capa_runner.h"
#include "pluginmain.h"
#include "_dbgfunctions.h"

#include <string>
#include <vector>
#include <cstdio>

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

bool GetDebuggedTargetPath(std::string& out)
{
    out.clear();

    char targetPath[MAX_PATH] = {};
    const duint base = Script::Module::GetMainModuleBase();
    const int n = DbgFunctions()->ModPathFromAddr(base, targetPath, MAX_PATH);
    if (n <= 0 || !targetPath[0])
        return false;

    out = targetPath;
    return true;
}

bool TargetFileExists(const std::string& path)
{
    if (path.empty())
        return false;

    const std::wstring wpath = AnsiToWide(path);
    if (wpath.empty())
        return false;

    const DWORD attr = GetFileAttributesW(wpath.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool RunCapaOnTarget(const std::string& capaExe,
                     const std::string& targetPath,
                     std::string& jsonOut)
{
    jsonOut.clear();

    if (capaExe.empty())
    {
        _plugin_logputs("[capa2dbg] capa_path bos.");
        return false;
    }
    if (targetPath.empty())
    {
        _plugin_logputs("[capa2dbg] Hedef yolu bos.");
        return false;
    }
    if (!TargetFileExists(targetPath))
    {
        _plugin_logprintf("[capa2dbg] Hedef dosya diskte bulunamadi: %s\n", targetPath.c_str());
        return false;
    }

    _plugin_logprintf("[capa2dbg] capa hedefi: %s\n", targetPath.c_str());

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE hRead = nullptr;
    HANDLE hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
    {
        _plugin_logputs("[capa2dbg] CreatePipe basarisiz.");
        return false;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    // Wide command line: capa is a Python (PyInstaller) build and reads
    // GetCommandLineW, so ANSI conversion would mangle non-ACP path characters.
    const std::wstring wCmd = L"\"" + AnsiToWide(capaExe) + L"\" -j -vv \"" +
                              AnsiToWide(targetPath) + L"\"";
    std::vector<wchar_t> cmdBuf(wCmd.begin(), wCmd.end());
    cmdBuf.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    const BOOL ok = CreateProcessW(
        nullptr,
        cmdBuf.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi);

    CloseHandle(hWrite);
    hWrite = nullptr;

    if (!ok)
    {
        CloseHandle(hRead);
        _plugin_logprintf("[capa2dbg] capa CreateProcess basarisiz (err=%lu). capa_path dogru mu?\n",
                          GetLastError());
        return false;
    }

    std::string out;
    char buf[4096];
    DWORD read = 0;
    while (ReadFile(hRead, buf, sizeof(buf), &read, nullptr) && read > 0)
        out.append(buf, buf + read);

    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (out.empty())
    {
        _plugin_logprintf("[capa2dbg] capa ciktisi bos (exit=%lu).\n", exitCode);
        return false;
    }

    if (exitCode != 0)
    {
        std::string head = out.substr(0, 200);
        for (auto& c : head)
        {
            if (c == '\r' || c == '\n')
                c = ' ';
        }
        _plugin_logprintf("[capa2dbg] capa hata verdi (exit=%lu): %s\n", exitCode, head.c_str());
        return false;
    }

    // capa may print non-JSON noise; keep from first '{' if present
    const size_t brace = out.find('{');
    if (brace != std::string::npos && brace > 0)
        out = out.substr(brace);

    jsonOut = std::move(out);
    _plugin_logprintf("[capa2dbg] capa bitti (exit=%lu, %zu byte JSON).\n",
                      exitCode, jsonOut.size());
    return true;
}
