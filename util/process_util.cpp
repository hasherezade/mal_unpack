#include "process_util.h"
#include <iostream>
#include <Psapi.h>
#include <tlhelp32.h>

#include "..\pe-sieve\utils\ntddk.h"
#include "..\driver_comm.h"

HANDLE create_new_process(IN LPSTR exe_path, IN LPSTR cmd, OUT PROCESS_INFORMATION &pi, DWORD flags, IN OPTIONAL ULONGLONG file_id, IN OPTIONAL DWORD noresp)
{
    static bool is_driver = driver::is_ready();

    //is the CREATE_SUSPENDED flag explicitly requested?
    const bool make_suspended = (flags & CREATE_SUSPENDED) ? true : false;
    if (is_driver) {
        flags = flags | CREATE_SUSPENDED;
    }
    std::string full_cmd = std::string(exe_path) + " " + std::string(cmd);
    STARTUPINFOA si;
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
#ifdef _DEBUG
    std::cout << "Commandline: " << cmd << std::endl;
#endif
    if (!CreateProcessA(
        exe_path,
        (LPSTR)full_cmd.c_str(),
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
    if (is_driver) {
        if (driver::watch_pid(pi.dwProcessId, file_id, noresp)) {
            std::cout << "[*] The process: " << std::dec << pi.dwProcessId << " is watched by the driver" << "\n";
        }
        else {
            std::cout << "[!] Could not create a watched process: " << std::dec << pi.dwProcessId << ". Terminating...\n";
            kill_pid(pi.dwProcessId);
            return NULL;
        }

    }
    if (!make_suspended && (flags & CREATE_SUSPENDED)) {
        ResumeThread(pi.hThread);
    }
    return pi.hProcess;
}

HANDLE make_new_process(IN char* targetPath, IN char* cmdLine, IN DWORD flags, IN OPTIONAL ULONGLONG file_id, IN OPTIONAL DWORD noresp)
{
    //create target process:
    PROCESS_INFORMATION pi;
    if (!create_new_process(targetPath, cmdLine, pi, flags, file_id, noresp)) {
        return NULL;
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

bool kill_pid(DWORD pid, bool force_non_critical)
{
    static bool is_driver = driver::is_ready();
    if (is_driver && driver::kill_watched_pid(pid)) {
        std::cout << "[*] The process: "<< std::dec << pid << " is sent to be terminated by the driver" << "\n";
        return true;
    }
#ifdef _DEBUG
    std::cout << "[!] Killing PID: " << std::dec << pid << std::endl;
#endif
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_SET_INFORMATION, FALSE, pid);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    }
    if (!hProcess) {
        const DWORD err = GetLastError();
        if (err == ERROR_INVALID_PARAMETER) {
            return true; // already killed
        }
        return false;
    }
    // try to set process as non-critical before killing:
    ULONG IsCritical = 0;
    if (force_non_critical) {
        const NTSTATUS status = NtSetInformationProcess(hProcess, ProcessBreakOnTermination, &IsCritical, sizeof(ULONG));
#ifdef _DEBUG
        std::cout << " NtSetInformationProcess , status: " << std::hex << status << std::endl;
#endif
    }
    bool is_killed = false;
    if (TerminateProcess(hProcess, 0)) {
        is_killed = true;
    }
    CloseHandle(hProcess);
    return is_killed;
}


/*
based on: https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
*/
BOOL set_privilege(
    HANDLE hToken,          // token handle
    LPCTSTR Privilege,      // Privilege to enable/disable
    BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    TOKEN_PRIVILEGES tpPrevious;
    DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

    if (!LookupPrivilegeValueA(nullptr, Privilege, &luid)) {
        return FALSE;
    }
    // get current privilege
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0;

    AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        &tpPrevious,
        &cbPrevious
    );

    if (GetLastError() != ERROR_SUCCESS) {
        return FALSE;
    }
    // set privilege based on previous setting
    tpPrevious.PrivilegeCount = 1;
    tpPrevious.Privileges[0].Luid = luid;

    if (bEnablePrivilege) {
        tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
    }
    else {
        tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);
    }

    AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tpPrevious,
        cbPrevious,
        NULL,
        NULL
    );

    if (GetLastError() != ERROR_SUCCESS) {
        return FALSE;
    }
    return TRUE;
}

bool set_debug_privilege()
{
    HANDLE hToken;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
        if (GetLastError() == ERROR_NO_TOKEN) {
            if (!ImpersonateSelf(SecurityImpersonation)) return false;
            if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
                std::cerr << "Error: cannot open the token" << std::endl;
                return false;
            }
        }
    }
    bool is_ok = false;
    // enable SeDebugPrivilege
    if (set_privilege(hToken, SE_DEBUG_NAME, TRUE)) {
        is_ok = true;
    }
    // close token handle
    CloseHandle(hToken);
    return is_ok;
}

size_t _map_processes_parent_to_children(std::set<DWORD> &pids, std::map<DWORD, std::set<DWORD> > &parentToChildrenMap)
{
    size_t count = 0;
    size_t scanned_count = 0;
    size_t ignored_count = 0;

    HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnapShot == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        std::cerr << "[-] Could not create modules snapshot. Error: " << std::dec << err << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnapShot, &pe32)) {
        CloseHandle(hProcessSnapShot);
        std::cerr << "[-] Could not enumerate processes. Error: " << GetLastError() << std::endl;
        return 0;
    }
    do {
        const DWORD pid = pe32.th32ProcessID;
        const DWORD parent = pe32.th32ParentProcessID;
        pids.insert(pid);

        if (parent != INVALID_PID_VALUE) {
            parentToChildrenMap[parent].insert(pid);
            count++;
        }
    } while (Process32Next(hProcessSnapShot, &pe32));

    //close the handles
    CloseHandle(hProcessSnapShot);
    return count;
}

std::wstring get_process_module_path(DWORD processID)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == NULL) {
        return L"";
    }
    HMODULE hMod;
    DWORD cbNeeded;
    WCHAR nameBuf[MAX_PATH];
    bool is_ok = false;
    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        GetModuleFileNameExW(hProcess, hMod, nameBuf, MAX_PATH);
        is_ok = true;
    }
    CloseHandle(hProcess);
    if (is_ok) {
        return nameBuf;
    }
    return L"";
}

size_t enum_modules(IN HANDLE hProcess, IN OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters)
{
    if (hProcess == nullptr) {
        return 0;
    }

    DWORD cbNeeded;
#ifdef _WIN64
    if (!EnumProcessModulesEx(hProcess, hMods, hModsMax, &cbNeeded, filters)) {
        return 0;
    }
#else
    /*
    Some old, 32-bit versions of Windows do not have EnumProcessModulesEx,
    but we can use EnumProcessModules for the 32-bit version: it will work the same and prevent the compatibility issues.
    */
    if (!EnumProcessModules(hProcess, hMods, hModsMax, &cbNeeded)) {
        return 0;
    }
#endif
    const size_t modules_count = cbNeeded / sizeof(HMODULE);
    return modules_count;
}

inline WCHAR to_lowercase(WCHAR c1)
{
    if (c1 <= L'Z' && c1 >= L'A') {
        c1 = (c1 - L'A') + L'a';
    }
    return c1;
}

bool is_wanted_module(const wchar_t* curr_name, const wchar_t* wanted_name)
{
    if (wanted_name == NULL || curr_name == NULL) return false;

    const wchar_t* curr_end_ptr = curr_name;
    while (*curr_end_ptr != L'\0') {
        curr_end_ptr++;
    }
    if (curr_end_ptr == curr_name) return false;

    const wchar_t* wanted_end_ptr = wanted_name;
    while (*wanted_end_ptr != L'\0') {
        wanted_end_ptr++;
    }
    if (wanted_end_ptr == wanted_name) return false;

    while ((curr_end_ptr != curr_name) && (wanted_end_ptr != wanted_name)) {

        if (to_lowercase(*wanted_end_ptr) != to_lowercase(*curr_end_ptr)) {
            return false;
        }
        wanted_end_ptr--;
        curr_end_ptr--;
    }
    return true;
}

HMODULE search_module_by_name(IN HANDLE hProcess, IN const std::wstring& searchedName)
{
    const DWORD hModsMax = 0x1000;
    HMODULE hMods[hModsMax] = { 0 };

    size_t modules_count = enum_modules(hProcess, hMods, hModsMax, LIST_MODULES_ALL);

    wchar_t nameBuf[MAX_PATH] = { 0 };

    size_t i = 0;
    for (i = 0; i < modules_count; i++) {
        HMODULE hMod = hMods[i];
        if (!hMod || hMod == INVALID_HANDLE_VALUE) break;

        memset(nameBuf, 0, sizeof(nameBuf));
        if (GetModuleFileNameExW(hProcess, hMod, nameBuf, MAX_PATH)) {
#ifdef _DEBUG
            std::wcout << nameBuf << "\n";
#endif
            if (is_wanted_module(nameBuf, (wchar_t*)searchedName.c_str())) {

                //std::wcout << "Matched " << nameBuf << "\n";

                return hMod;
            }
        }
    }
    return NULL;
}

bool is_module_in_process(DWORD pid, const wchar_t* dll_path)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    HANDLE fMod = search_module_by_name(hProcess, dll_path);
    bool isFound = false;
    if (fMod) {
        isFound = true;
    }
    CloseHandle(hProcess);
    return isFound;
}
