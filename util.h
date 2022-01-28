#pragma once

#include <Windows.h>

#include <string>
#include <iostream>
#include <sstream>
#include <pe_sieve_api.h>

std::string version_to_str(DWORD version);

std::string make_dir_name(std::string baseDir, time_t timestamp);

bool set_output_dir(pesieve::t_params &args, const char *new_dir);

const char* get_file_name(const char* full_path);
