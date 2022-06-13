#pragma once

#include <windows.h>
#include <psapi.h>
#include <string>
#include <map>
#include <set>

#define INVALID_PID_VALUE (DWORD)(-1)

HANDLE create_new_process(IN LPSTR exe_path, IN LPSTR cmd, OUT PROCESS_INFORMATION &pi, DWORD flags, IN OPTIONAL ULONGLONG file_id, IN OPTIONAL DWORD noresp);

HANDLE make_new_process(IN char* targetPath, IN char* cmdLine, IN DWORD flags, IN OPTIONAL ULONGLONG file_id, IN OPTIONAL DWORD noresp);

DWORD get_parent_pid(DWORD my_pid);

bool kill_pid(DWORD pid, bool force_non_critical=true);

bool set_debug_privilege();

size_t _map_processes_parent_to_children(std::set<DWORD> &pids, std::map<DWORD, std::set<DWORD> > &parentToChildrenMap);

std::wstring get_process_module_path(DWORD processID);

bool is_module_in_process(DWORD pid, const wchar_t* dll_path);

bool is_wanted_module(const wchar_t* curr_name, const wchar_t* wanted_name);
