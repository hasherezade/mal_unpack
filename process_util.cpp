#include "process_util.h"
#include <iostream>

HANDLE create_new_process(IN LPSTR path, OUT PROCESS_INFORMATION &pi, DWORD flags)
{
    STARTUPINFOA si;
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    if (!CreateProcessA(
        NULL,
        path,
        NULL, //lpProcessAttributes
        NULL, //lpThreadAttributes
        FALSE, //bInheritHandles
        flags, //dwCreationFlags
        NULL, //lpEnvironment 
        NULL, //lpCurrentDirectory
        &si, //lpStartupInfo
        &pi //lpProcessInformation
    ))
    {
#ifdef _DEBUG
        std::cerr << "[ERROR] CreateProcess failed, Error = " << GetLastError() << std::endl;
#endif
        return NULL;
    }
    return pi.hProcess;
}

HANDLE make_new_process(char* targetPath, DWORD flags)
{
    //create target process:
    PROCESS_INFORMATION pi;
    if (!create_new_process(targetPath, pi, flags)) {
        return false;
    }
#ifdef _DEBUG
    std::cout << "PID: " << std::dec << pi.dwProcessId << std::endl;
#endif
    return pi.hProcess;
}

