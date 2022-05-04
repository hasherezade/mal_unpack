#pragma once

#include <windows.h>
#include <iostream>

namespace driver {

	enum class DriverStatus {
		DRIVER_UNKNOWN,
		DRIVER_MALFORMED_REQUEST,
		DRIVER_UNAVAILABLE,
		DRIVER_NOT_RESPONDING,
		DRIVER_OK
	};


	bool is_ready();

	DriverStatus get_version(char* buf, size_t buf_len, ULONGLONG& nodesCount);

	bool watch_pid(DWORD pid, ULONGLONG fileId, DWORD noresp);

	bool kill_watched_pid(DWORD pid);

	bool delete_watched_file(DWORD pid, const std::wstring& filename);

	bool fetch_watched_processes(DWORD startPID, DWORD out_buffer[], size_t out_count);

	bool fetch_watched_files(DWORD startPID, LONGLONG out_buffer[], size_t out_count);
};

