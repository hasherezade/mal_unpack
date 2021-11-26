#pragma once

#include <windows.h>

typedef enum {
	DACTION_NONE = (-1),
	DACTION_UNREGISTER = 0,
	DACTION_REGISTER = 1,
	DACTION_KILL = 2
} driver_action;

bool is_driver_ready();

bool request_driver_action(driver_action action, DWORD pid);
