#pragma once

#include <windows.h>

namespace driver {

	bool is_ready();

	bool watch_pid(DWORD pid);

	bool kill_watched_pid(DWORD pid);

	bool fetch_watched_processes(DWORD startPID, DWORD out_buffer[], size_t out_count);

	bool fetch_watched_files(DWORD startPID, LONGLONG out_buffer[], size_t out_count);
};

