#include "process_util.h"
#include <iostream>
#include <Psapi.h>
#include "pe-sieve\utils\ntddk.h"

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

DWORD get_parent_pid(DWORD dwPID)
{
    NTSTATUS ntStatus;
    DWORD dwParentPID = INVALID_PID_VALUE;
    HANDLE hProcess;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG ulRetLen;

    //  create entry point for 'NtQueryInformationProcess()'
    typedef NTSTATUS(__stdcall *FPTR_NtQueryInformationProcess) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

    FPTR_NtQueryInformationProcess NtQueryInformationProcess
        = (FPTR_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");

    //  get process handle
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION,
        FALSE,
        dwPID
    );
    //  could fail due to invalid PID or insufficiant privileges
    if (!hProcess)
        return  INVALID_PID_VALUE;
    //  gather information
    ntStatus = NtQueryInformationProcess(hProcess,
        ProcessBasicInformation,
        (void*)&pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ulRetLen
    );
    //  copy PID on success
    if (!ntStatus)
        dwParentPID = (DWORD)pbi.InheritedFromUniqueProcessId;
    CloseHandle(hProcess);
    return  (dwParentPID);
}

bool kill_pid(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        return false;
    }
    bool is_killed = false;
    if (TerminateProcess(hProcess, 0)) {
        is_killed = true;
    }
    CloseHandle(hProcess);
    return is_killed;
}

bool kill_till_dead(HANDLE &proc)
{
    bool is_killed = false;
    //terminate the original process (if not terminated yet)
    DWORD exit_code = 0;
    do {
        GetExitCodeProcess(proc, &exit_code);
        if (exit_code == STILL_ACTIVE) {
            TerminateProcess(proc, 0);
        }
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            std::cerr << "Could not kill the process: access denied!" << std::endl;
            break; //process is elevated, cannot kill it:
        }
        else {
            is_killed = true;
            break;
        }
    } while (true);
    return is_killed;
}

bool kill_till_dead_pid(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        return false;
    }
    bool is_killed = kill_till_dead(hProcess);
    CloseHandle(hProcess);
    return is_killed;
}
