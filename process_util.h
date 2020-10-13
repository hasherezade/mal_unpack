#pragma once

#include  <Windows.h>
#include <psapi.h>

#define INVALID_PID_VALUE (DWORD)(-1)

HANDLE create_new_process(IN LPSTR path, OUT PROCESS_INFORMATION &pi, DWORD flags);

HANDLE make_new_process(char* targetPath, DWORD flags);

DWORD get_parent_pid(DWORD my_pid);

bool kill_pid(DWORD pid);

bool kill_till_dead(HANDLE &proc);
bool kill_till_dead_pid(DWORD pid);

bool set_debug_privilege();
