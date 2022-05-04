#include "driver_comm.h"

#include <iostream>

struct ProcessDataBasic {
	DWORD Id;
};

struct ProcessDataEx_v2 {
	ULONG Pid;
	LONGLONG fileId;
	ULONG noresp; //respawn protection level
};

typedef ProcessDataEx_v2 ProcessDataEx;

#define DRIVER_PATH  L"\\\\.\\MalUnpackCompanion"
#define MUNPACK_COMPANION_DEVICE 0x8000

#define IOCTL_MUNPACK_COMPANION_VERSION CTL_CODE(MUNPACK_COMPANION_DEVICE, \
	0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MUNPACK_COMPANION_ADD_TO_WATCHED CTL_CODE(MUNPACK_COMPANION_DEVICE, \
	0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MUNPACK_COMPANION_TERMINATE_WATCHED CTL_CODE(MUNPACK_COMPANION_DEVICE, \
	0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MUNPACK_COMPANION_LIST_PROCESSES CTL_CODE(MUNPACK_COMPANION_DEVICE, \
	0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MUNPACK_COMPANION_LIST_FILES CTL_CODE(MUNPACK_COMPANION_DEVICE, \
	0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MUNPACK_COMPANION_COUNT_NODES CTL_CODE(MUNPACK_COMPANION_DEVICE, \
	0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)


namespace driver {

	template<typename T>
	void list_buffer(T* out_buffer, size_t out_count, bool print_hex)
	{
		std::cout << "{ ";
		for (size_t i = 0; i < out_count; i++) {
			if (out_buffer[i] == 0) break;
			if (i != 0) {
				std::cout << ", ";
			}
			if (print_hex) {
				std::cout << std::hex << out_buffer[i];
			}
			else {
				std::cout << std::dec << out_buffer[i];
			}
		}
		std::cout << " }\n";
	}

	template<typename T>
	bool fetch_watched_elements(DWORD ioctl, DWORD startPID, T out_buffer[], size_t out_count)
	{
		if (!out_buffer || !out_count || !ioctl) {
			return false;
		}
		HANDLE hDevice = CreateFileW(DRIVER_PATH, GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hDevice == INVALID_HANDLE_VALUE) {
			std::cerr << "Failed to open device" << std::endl;
			return false;
		}
		size_t out_size = out_count * sizeof(T); // size in bytes
		DWORD returned = 0;
		BOOL success = DeviceIoControl(hDevice, ioctl, &startPID, sizeof(startPID), out_buffer, out_size, &returned, nullptr);
		CloseHandle(hDevice);
		return success == TRUE ? true : false;
	}

	bool request_action_on_pid(DWORD ioctl, DWORD pid)
	{
		if (!ioctl || !pid) {
			return false;
		}
		HANDLE hDevice = CreateFileW(DRIVER_PATH, GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hDevice == INVALID_HANDLE_VALUE) {
			std::cerr << "Failed to open device" << std::endl;
			return false;
		}

		ProcessDataBasic data = { 0 };
		data.Id = pid;

		BOOL success = FALSE;
		DWORD returned = 0;
		success = DeviceIoControl(hDevice, ioctl, &data, sizeof(data), nullptr, 0, &returned, nullptr);
		CloseHandle(hDevice);
		return success == TRUE ? true : false;
	}
};

bool driver::is_ready()
{
	HANDLE hDevice = CreateFileW(DRIVER_PATH, GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		return false;
	}
	CloseHandle(hDevice);
	return true;
}

typedef struct {
	HANDLE hDevice;
	char* buf;
	DWORD buf_size;
	DWORD returned_size;
	ULONGLONG nodesCount;
	BOOL success;
} t_driver_version_args;

DWORD WINAPI query_driver_version(LPVOID lpParam)
{
	t_driver_version_args* args = static_cast<t_driver_version_args*>(lpParam);
	if (!args) {
		return !S_OK;
	}
	BOOL success = DeviceIoControl(args->hDevice, IOCTL_MUNPACK_COMPANION_VERSION, 0, 0, args->buf, args->buf_size, &args->returned_size, nullptr);
	if (!success) {
		return !S_OK;
	}
	DWORD returned = 0;
	success = DeviceIoControl(args->hDevice, IOCTL_MUNPACK_COMPANION_COUNT_NODES, 0, 0, &args->nodesCount, sizeof(args->nodesCount), &returned, nullptr);
	if (!success) {
		return !S_OK;
	}
	args->success = success;
	return !S_OK;
}

driver::DriverStatus driver::get_version(char* out_buffer, size_t buf_len, ULONGLONG &nodesCount)
{
	const DWORD max_wait = 1000;
	if (!out_buffer || !buf_len) {
		return DriverStatus::DRIVER_MALFORMED_REQUEST;
	}
	HANDLE hDevice = CreateFileW(DRIVER_PATH, GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		return DriverStatus::DRIVER_UNAVAILABLE;
	}

	t_driver_version_args args = { 0 };
	args.buf = out_buffer;
	args.buf_size = buf_len;
	args.hDevice = hDevice;
	args.success = false;

	DriverStatus status = DriverStatus::DRIVER_UNKNOWN;
	HANDLE hThread = CreateThread(NULL, 0, query_driver_version, &args, 0, 0);
	DWORD wait_result = WaitForSingleObject(hThread, max_wait);
	if (wait_result == WAIT_TIMEOUT) {
		TerminateThread(hThread, 0);
		status = DriverStatus::DRIVER_NOT_RESPONDING;
	}
	CloseHandle(hDevice);
	if (args.success) {
		nodesCount = args.nodesCount;
		status = DriverStatus::DRIVER_OK;
	}
	return status;
}

bool driver::fetch_watched_processes(DWORD startPID, DWORD out_buffer[], size_t out_count)
{
	static bool isReady = is_ready();
	if (!isReady) {
		return false;
	}
	bool isOK = fetch_watched_elements(IOCTL_MUNPACK_COMPANION_LIST_PROCESSES, startPID, out_buffer, out_count);
	if (isOK) {
		std::cout << "Processes retrieved by the driver:\n";
		list_buffer(out_buffer, out_count, false);
	}
	return isOK;
}

bool driver::fetch_watched_files(DWORD startPID, LONGLONG out_buffer[], size_t out_count)
{
	static bool isReady = is_ready();
	if (!isReady) {
		return false;
	}
	bool isOK = fetch_watched_elements(IOCTL_MUNPACK_COMPANION_LIST_FILES, startPID, out_buffer, out_count);
	if (isOK) {
		std::cout << "FileIDs retrieved by the driver:\n";
		list_buffer(out_buffer, out_count, true);
	}
	return isOK;
}


bool driver::watch_pid(DWORD pid, ULONGLONG fileId, DWORD noresp)
{
	if (!pid) {
		return false;
	}
	HANDLE hDevice = CreateFileW(DRIVER_PATH, GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open device" << std::endl;
		return false;
	}

	ProcessDataEx data = { 0 };
	data.Pid = pid;
	data.fileId = fileId;
	data.noresp = noresp;

	BOOL success = FALSE;
	DWORD returned = 0;
	success = DeviceIoControl(hDevice, IOCTL_MUNPACK_COMPANION_ADD_TO_WATCHED, &data, sizeof(data), nullptr, 0, &returned, nullptr);
	CloseHandle(hDevice);
	return success == TRUE ? true : false;
}

bool driver::kill_watched_pid(DWORD pid)
{
	return driver::request_action_on_pid(IOCTL_MUNPACK_COMPANION_TERMINATE_WATCHED, pid);
}
