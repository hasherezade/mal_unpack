#pragma once

#include <windows.h>

#include <string>
#include <iostream>
#include <sstream>
#include <pe_sieve_api.h>

std::string make_dir_name(std::string baseDir, time_t timestamp, std::string prefix);

const char* get_file_name(const char* full_path);
