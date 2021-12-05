#pragma once

#include <windows.h>
#include <iostream>
#include <set>

namespace file_util {

	size_t delete_dropped_files(std::set<ULONGLONG>& allDroppedFiles);
}
