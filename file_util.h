#pragma once

#include <windows.h>
#include <iostream>
#include <string>
#include <set>
#include <map>

namespace file_util {

	typedef struct _delete_results {
		size_t deleted_count;
		size_t moved_count;
	} delete_results;

	std::wstring get_file_path(IN const char* filename);

	ULONGLONG get_file_id(IN const char* img_path);

	size_t file_ids_to_names(IN std::set<LONGLONG>& filesIds, OUT std::map<LONGLONG, std::wstring> &names, IN OPTIONAL DWORD name_type);

	delete_results delete_or_move_files(IN OUT std::map<LONGLONG, std::wstring>& names, IN time_t timestamp, IN const std::wstring &suffix_to_add);
}
