#include "driver_comm.h"

#include <iostream>

struct ProcessData {
	unsigned long Id;
};

#define DRIVER_PATH  L"\\\\.\\MyDriver1"
#define PROCESS_WATCHER_DEVICE 0x8000

#define IOCTL_PROCESS_WATCHER_ADD_TO_WATCHED CTL_CODE(PROCESS_WATCHER_DEVICE, \
	0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_PROCESS_WATCHER_REMOVE_FROM_WATCHED CTL_CODE(PROCESS_WATCHER_DEVICE, \
	0x801, METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_PROCESS_WATCHER_TERMINATE_WATCHED CTL_CODE(PROCESS_WATCHER_DEVICE, \
	0x802, METHOD_NEITHER, FILE_ANY_ACCESS)


DWORD action_to_ioctl(driver_action action)
{
	switch (action) {
	case DACTION_UNREGISTER: return IOCTL_PROCESS_WATCHER_REMOVE_FROM_WATCHED;
	case DACTION_REGISTER: return IOCTL_PROCESS_WATCHER_ADD_TO_WATCHED;
	case DACTION_KILL: return IOCTL_PROCESS_WATCHER_TERMINATE_WATCHED;
	}
	return 0;
}

bool is_driver_ready()
{
	HANDLE hDevice = CreateFileW(DRIVER_PATH, GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		return false;
	}
	CloseHandle(hDevice);
	return true;
}

bool request_driver_action(driver_action action, DWORD pid)
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
