#include "driver_comm.h"

#include <iostream>


struct ProcessData {
	unsigned long Id;
};

#define DRIVER_PATH  L"\\\\.\\MalUnpackCompanion"
#define MUNPACK_COMPANION_DEVICE 0x8000


#define IOCTL_MUNPACK_COMPANION_ADD_TO_WATCHED CTL_CODE(MUNPACK_COMPANION_DEVICE, \
	0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MUNPACK_COMPANION_TERMINATE_WATCHED CTL_CODE(MUNPACK_COMPANION_DEVICE, \
	0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MUNPACK_COMPANION_LIST_PROCESSES CTL_CODE(MUNPACK_COMPANION_DEVICE, \
	0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MUNPACK_COMPANION_LIST_FILES CTL_CODE(MUNPACK_COMPANION_DEVICE, \
	0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)


namespace driver {
	DWORD action_to_ioctl(driver_action action)
	{
		switch (action) {
		case DACTION_REGISTER: return IOCTL_MUNPACK_COMPANION_ADD_TO_WATCHED;
		case DACTION_KILL: return IOCTL_MUNPACK_COMPANION_TERMINATE_WATCHED;
		}
		return 0;
	}

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
		if (!out_buffer || !out_count) {
			return false;
		}
		HANDLE hDevice = CreateFileW(DRIVER_PATH, GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hDevice == INVALID_HANDLE_VALUE) {
			std::cerr << "Failed to open device" << std::endl;
			return 1;
		}
		size_t out_size = out_count * sizeof(T); // size in bytes
		DWORD returned = 0;
		BOOL success = DeviceIoControl(hDevice, ioctl, &startPID, sizeof(startPID), out_buffer, out_size, &returned, nullptr);
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

bool driver::request_action(driver_action action, DWORD pid)
{
	HANDLE hDevice = CreateFileW(DRIVER_PATH, GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open device" << std::endl;
		return 1;
	}

	ProcessData data = { 0 };
	data.Id = pid;

	BOOL success = FALSE;
	DWORD ioctl = action_to_ioctl(action);
	if (ioctl != 0) {
		DWORD returned = 0;
		success = DeviceIoControl(hDevice, ioctl, &data, sizeof(data), nullptr, 0, &returned, nullptr);
		if (success) {
			std::cout << "[OK] The action completed successfuly" << std::endl;
		}
		else {
			std::cout << "The action failed! " << std::endl;
		}
	}
	else {
		std::cout << "Invalid action requested! " << std::endl;
	}

	CloseHandle(hDevice);
	return success == TRUE ? true : false;
}
