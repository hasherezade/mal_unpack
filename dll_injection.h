#pragma once

#include <windows.h>

bool inject_with_loadlibrary(HANDLE hProcess, const char *inject_path);
