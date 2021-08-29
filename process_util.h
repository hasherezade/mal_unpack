#pragma once

#include  <Windows.h>
#include <psapi.h>

#define INVALID_PID_VALUE (DWORD)(-1)

HANDLE create_new_process(IN LPSTR exe_path, IN LPSTR cmd, OUT PROCESS_INFORMATION &pi, DWORD flags);

HANDLE make_new_process(char* targetPath, char* cmdLine, DWORD flags);

DWORD get_parent_pid(DWORD my_pid);

bool kill_pid(DWORD pid);

bool set_debug_privilege();
