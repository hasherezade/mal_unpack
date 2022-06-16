#pragma once

#include <windows.h>

#include <string>
#include <iostream>
#include <sstream>

std::string make_dir_name(std::string baseDir, time_t timestamp, const std::string &prefix);

const char* get_file_name(const char* full_path);
