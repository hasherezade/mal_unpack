#pragma once

#include <windows.h>

namespace driver {

	enum class DriverStatus {
		DRIVER_UNKNOWN,
		DRIVER_MALFORMED_REQUEST,
		DRIVER_UNAVAILABLE,
		DRIVER_NOT_RESPONDING,
		DRIVER_OK
	};

	bool is_ready();

	DriverStatus get_version(char* buf, size_t buf_len);

	bool watch_pid(DWORD pid, ULONGLONG fileId);

	bool kill_watched_pid(DWORD pid);

	bool fetch_watched_processes(DWORD startPID, DWORD out_buffer[], size_t out_count);

	bool fetch_watched_files(DWORD startPID, LONGLONG out_buffer[], size_t out_count);
};

