#pragma once

#include <windows.h>
#include <iostream>
#include <string>
#include <set>

namespace file_util {

	size_t file_ids_to_names(std::set<LONGLONG>& filesIds, std::set<std::wstring> &names);

	size_t delete_dropped_files(std::set<std::wstring>& names);
}
