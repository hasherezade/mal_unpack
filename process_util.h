#pragma once

#include  <Windows.h>
#include <psapi.h>

HANDLE create_new_process(IN LPSTR path, OUT PROCESS_INFORMATION &pi, DWORD flags);

HANDLE make_new_process(char* targetPath, DWORD flags);
