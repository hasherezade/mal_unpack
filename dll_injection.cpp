#include "dll_injection.h"

#include <iostream>
#include <psapi.h>

#define INJ_TIMEOUT 100000

LPVOID write_into_process(HANDLE hProcess, LPBYTE buffer, SIZE_T buffer_size, DWORD protect)
{
    LPVOID remoteAddress = VirtualAllocEx(hProcess, NULL, buffer_size, MEM_COMMIT | MEM_RESERVE, protect);
    if (remoteAddress == NULL) {
        std::cerr << "Could not allocate memory in the remote process\n";
        return NULL;
    }
    if (!WriteProcessMemory(hProcess, remoteAddress, buffer, buffer_size, NULL)) {
        VirtualFreeEx(hProcess, remoteAddress, buffer_size, MEM_FREE);
        return NULL;
    }
    return remoteAddress;
}


size_t enum_modules(IN HANDLE hProcess, IN OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters) //throws exceptions
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

inline char to_lowercase(char c1)
{
    if (c1 <= 'Z' && c1 >= 'A') {
        c1 = (c1 - 'A') + 'a';
    }
    return c1;
}

bool is_wanted_module(char* curr_name, char* wanted_name)
{
    if (wanted_name == NULL || curr_name == NULL) return false;

    char *curr_end_ptr = curr_name;
    while (*curr_end_ptr != '\0') {
        curr_end_ptr++;
    }
    if (curr_end_ptr == curr_name) return false;

    char *wanted_end_ptr = wanted_name;
    while (*wanted_end_ptr != '\0') {
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

HMODULE search_module_by_name(IN HANDLE hProcess, IN const std::string &searchedName)
{
    const DWORD hModsMax = 0x1000;
    HMODULE hMods[hModsMax] = { 0 };

    size_t modules_count = enum_modules(hProcess, hMods, hModsMax, LIST_MODULES_ALL);

    char nameBuf[MAX_PATH] = { 0 };

    size_t i = 0;
    for (i = 0; i < modules_count; i++) {
        HMODULE hMod = hMods[i];
        if (!hMod || hMod == INVALID_HANDLE_VALUE) break;

        memset(nameBuf, 0, sizeof(nameBuf));
        if (GetModuleFileNameExA(hProcess, hMod, nameBuf, MAX_PATH)) {
#ifdef _DEBUG
            std::wcout << nameBuf << "\n";
#endif
            if (is_wanted_module(nameBuf, (char*)searchedName.c_str())) {

                return hMod;
            }
        }
    }
    return NULL;
}

bool is_module_in_process(HANDLE hProcess, const char *dll_path)
{
    HANDLE fMod = search_module_by_name(hProcess, dll_path);
    bool isFound = false;
    if (fMod) {
        isFound = true;
    }
    CloseHandle(hProcess);
    return isFound;
}

bool inject_with_loadlibrary(HANDLE hProcess, const char *inject_path)
{
    if (!inject_path) {
        return false;
    }
    HMODULE hModule = GetModuleHandleW(L"kernel32.dll");
    if (!hModule) return false;

    FARPROC hLoadLib = GetProcAddress(hModule, "LoadLibraryA");
    if (!hLoadLib) return false;

    //calculate size along with the terminating '\0'
    SIZE_T inject_path_size = (strlen(inject_path) + 1) * sizeof(inject_path[0]);

    // write the full path of the DLL into the remote process:
    PVOID remote_ptr = write_into_process(hProcess, (BYTE*)inject_path, inject_path_size, PAGE_READWRITE);
    if (!remote_ptr) {
        std::cerr << "Writing to process failed: " << std::hex << GetLastError() << "\n";
        return false;
    }
#ifdef _DEBUG
    std::cout << "[" << GetProcessId(hProcess) << "] Path writen to: " << remote_ptr << "\n";
#endif
    // Inject to the remote process:
    DWORD ret = WAIT_FAILED;
    HANDLE hndl = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLib, remote_ptr, NULL, NULL);
    if (hndl) {
        ret = WaitForSingleObject(hndl, INJ_TIMEOUT);
    }
    else {
        std::cout << "Creating thread failed!\n";
    }
    // cleanup:
    VirtualFreeEx(hProcess, remote_ptr, 0, MEM_RELEASE);

    if (is_module_in_process(hProcess, inject_path)) {
        return true;
    }
    return false;
}
