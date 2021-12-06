#pragma once

#include <windows.h>
#include <psapi.h>
#include <string>
#include <map>
#include <set>

#define INVALID_PID_VALUE (DWORD)(-1)

HANDLE create_new_process(IN LPSTR exe_path, IN LPSTR cmd, OUT PROCESS_INFORMATION &pi, DWORD flags);

HANDLE make_new_process(char* targetPath, char* cmdLine, DWORD flags);

DWORD get_parent_pid(DWORD my_pid);

bool kill_pid(DWORD pid);

bool set_debug_privilege();

size_t _map_processes_parent_to_children(std::set<DWORD> &pids, std::map<DWORD, std::set<DWORD> > &parentToChildrenMap);

bool get_process_name(IN HANDLE hProcess, OUT LPSTR nameBuf, IN DWORD nameMax);

std::string get_process_name_str(DWORD processID);
