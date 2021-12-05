#pragma once

#include <windows.h>

typedef enum {
	DACTION_NONE = (-1),
	DACTION_REGISTER = 1,
	DACTION_KILL = 2
} driver_action;

namespace driver {

	bool is_ready();

	bool request_action(driver_action action, DWORD pid);

	bool fetch_watched_processes(DWORD startPID, DWORD out_buffer[], size_t out_count);

	bool fetch_watched_files(DWORD startPID, LONGLONG out_buffer[], size_t out_count);
};

