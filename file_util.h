#pragma once

#include <windows.h>
#include <iostream>
#include <set>

namespace file_util {

	size_t list_files(std::set<LONGLONG>& filesIds);

	size_t delete_dropped_files(std::set<LONGLONG>& filesIds);
}
