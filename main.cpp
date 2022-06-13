#include <stdio.h>
#include <time.h>

#include <string>
#include <vector>
#include <iostream>
#include <sstream>

#include "params.h"

// basic file operations
#include <iostream>
#include <fstream>
#include <pe_sieve_return_codes.h>

#include "unpack_scanner.h"
#include "version.h"

#include "util/process_util.h"
#include "util/path_util.h"
#include "util/file_util.h"

#define WAIT_FOR_PROCESS_TIMEOUT 5000

#define VERSION VER_FILEVERSION_STR
#define LOG_FILE_NAME "unpack.log"

void print_log_hdr(std::wofstream &report, const time_t& session_timestamp, const t_params_struct& params)
{
    report << "[" << session_timestamp << "] ";

    const char* exe_name = get_file_name(params.exe_path);
    const char* img_name = get_file_name(params.img_path);
    if (exe_name) {
        report << exe_name;
    }
    if (img_name && exe_name && 
        strlen(img_name) && strcmp(img_name, exe_name) != 0)
    {
        report << " (" << img_name << ")";
    }
    report << " : ";
}

void save_unpack_report(const time_t &session_timestamp, t_params_struct &params, const ScanStats& finalStats)
{
    std::wofstream report;
    std::string report_name = LOG_FILE_NAME;
    report.open(report_name, std::ofstream::out | std::ofstream::app);
    print_log_hdr(report, session_timestamp, params);

    if (finalStats.detected) {
        report << "Unpacked in: " << std::dec << finalStats.scanTime << " ms\n";
    }
    else {
        report << "Failed to unpack\n";
    }
    report.close();
}

void save_remaing_files_report(const time_t& session_timestamp, t_params_struct& params, UnpackScanner& scanner)
{
    std::map<LONGLONG, std::wstring> names;
    if (!scanner.listExistingDroppedFiles(names)) {
        return;
    }

    std::wofstream report;
    std::string report_name = LOG_FILE_NAME;
    report.open(report_name, std::ofstream::out | std::ofstream::app);
    print_log_hdr(report, session_timestamp, params);

    report << "Failed to delete files (" << std::dec << names.size() << "):\n";
    std::map<LONGLONG, std::wstring>::const_iterator itr;
    for (itr = names.begin(); itr != names.end(); ++itr) {
        report << "> \"" << itr->second << "\"\n";
    }
    report.close();
}

void init_defaults(t_params_struct &params)
{
    UnpackScanner::args_init(params.hh_args);
    params.trigger = t_term_trigger::TRIG_ANY;
#ifdef _DEFAULT_CACHE
    params.hh_args.pesieve_args.use_cache = true;
#endif
}

bool get_watched_file_id(const t_params_struct& params, ULONGLONG &file_id)
{
    bool is_diffrent = false;
    file_id = FILE_INVALID_FILE_ID;

    if (strnlen(params.img_path, MAX_PATH) > 0
        && strncmp(params.img_path, params.exe_path, MAX_PATH) != 0)
    {
        file_id = file_util::get_file_id(params.img_path);
        is_diffrent = true;
    }
    if (file_id == FILE_INVALID_FILE_ID) {
        file_id = file_util::get_file_id(params.exe_path);
        is_diffrent = false;
    }
    if (is_diffrent) {
        std::cout << "[*] Watch respawns from the IMG: " << params.img_path << "\n";
    }
    else {
        std::cout << "[*] Watch respawns from main EXE file: " << params.exe_path << "\n";
    }
    return is_diffrent;
}

bool set_output_dir(pesieve::t_params& args, const char* new_dir)
{
    if (!new_dir) return false;

    size_t new_len = strlen(new_dir);
    size_t buffer_len = sizeof(args.output_dir);
    if (new_len > buffer_len) return false;

    memset(args.output_dir, 0, buffer_len);
    memcpy(args.output_dir, new_dir, new_len);
    return true;
}

int main(int argc, char* argv[])
{
    UnpackParams uParams(VERSION);
    t_params_struct params = { 0 };
    init_defaults(params);

    if (argc < 2) {
        uParams.printBanner();
        uParams.printBriefInfo();
        system("pause");
        return PESIEVE_INFO;
    }
    if (!uParams.parse(argc, argv)) {
        return PESIEVE_INFO;
    }
    if (!set_debug_privilege()) {
        std::cerr << "[-] Could not set debug privilege" << std::endl;
    }
    uParams.fillStruct(params);
    if (params.hh_args.pesieve_args.use_cache) {
        std::cout << "[*] Cache is Enabled!" << std::endl;
    }
    else {
        std::cout << "[*] Cache is Disabled!" << std::endl;
    }
    params.hh_args.kill_suspicious = true;
    // if the timeout was chosen as the trigger, don't interfere in the process:
    if (params.trigger == t_term_trigger::TRIG_TIMEOUT) {
        params.hh_args.kill_suspicious = false;
    }
    // if scanning of inaccessible pages was requested, auto-enable reflection mode:
    if (params.hh_args.pesieve_args.data == pesieve::PE_DATA_SCAN_INACCESSIBLE || params.hh_args.pesieve_args.data == pesieve::PE_DATA_SCAN_INACCESSIBLE_ONLY) {
        if (!params.hh_args.pesieve_args.make_reflection) {
            params.hh_args.pesieve_args.make_reflection = true;
            print_in_color(RED, "[WARNING] Scanning of inaccessible pages requested: auto-enabled reflection mode!\n");
        }
    }
    std::cout << "Starting the process: " << params.exe_path << std::endl;
    std::cout << "With commandline: \"" << params.exe_cmd << "\"" << std::endl;

    std::string file_name = get_file_name(params.exe_path);
    std::cout << "Exe name: " << file_name << std::endl;

    DWORD timeout = params.timeout;
    std::string root_dir = file_name + ".out";
    if (strlen(params.out_dir) > 0) {
        root_dir = std::string(params.out_dir) + "\\" + root_dir;
    }
    std::cout << "Root Dir: " << root_dir << "\n";

    t_pesieve_res ret_code = PESIEVE_ERROR;
    const DWORD flags = DETACHED_PROCESS | CREATE_NO_WINDOW;

    ULONGLONG file_id = FILE_INVALID_FILE_ID;
    bool is_img_diff = get_watched_file_id(params, file_id);
    HANDLE proc = make_new_process(params.exe_path, params.exe_cmd, flags, file_id, params.noresp);
    if (!proc) {
        std::cerr << "Could not start the process!" << std::endl;
        return ret_code;
    }
    params.hh_args.is_main_module = is_img_diff ? false : true;
    params.hh_args.module_path = (is_img_diff) ? file_util::get_file_path(params.img_path) : file_util::get_file_path(params.exe_path);
    std::wcout << "Module Path retrieved: " << params.hh_args.module_path << "\n";
    params.hh_args.start_pid = GetProcessId(proc);

    const time_t session_timestamp = time(NULL);
    const std::string out_dir = make_dir_name(root_dir, session_timestamp, "scan_");
    set_output_dir(params.hh_args.pesieve_args, out_dir.c_str());

    ULONGLONG start_tick = GetTickCount64();
    size_t count = 0;

    bool is_unpacked = false;
    UnpackScanner scanner(params.hh_args);
    ScanStats finalStats;
    do {
        ULONGLONG curr_time = GetTickCount64() - start_tick;
        if ((timeout != -1 && timeout > 0) && curr_time > timeout) {
            std::cout << "Unpack timeout passed!" << std::endl;
            ret_code = PESIEVE_NOT_DETECTED;
            break;
        }
        count++;
        std::cout << "Scanning..." << std::endl;
        ScanStats stats = scanner.scan();
        
        if (stats.scanned == 0) {
            if (curr_time < WAIT_FOR_PROCESS_TIMEOUT) {
                std::cout << "Nothing to scan... Waiting for a process: " << (WAIT_FOR_PROCESS_TIMEOUT - curr_time) << "ms\n";
            }
            else {
                std::cout << "Waiting timeout passed!" << std::endl;
                ret_code = PESIEVE_NOT_DETECTED;
                break;
            }
        }
        if (stats.detected > 0) {
            finalStats.detected++;
            is_unpacked = true;
            if (params.trigger == t_term_trigger::TRIG_ANY) {
                std::cout << "Suspicious detected, breaking!" << std::endl;
                break;
            }
        }
    } while (params.hh_args.loop_scanning);

    finalStats.scanTime = GetTickCount64() - start_tick;
    
    //this works only with the companion driver:
    if (scanner.collectDroppedFiles(file_id)) {
        std::cout << "The process dropped some files!\n";
    }

    save_unpack_report(session_timestamp, params, finalStats);

    if (is_unpacked) {
        std::cout << "Unpacked in: " << std::dec << finalStats.scanTime << " milliseconds; " << count << " attempts." << std::endl;
        ret_code = PESIEVE_DETECTED;
    }
    if (kill_pid(params.hh_args.start_pid)) {
        std::cout << "[OK] The initial process got killed." << std::endl;
    }
    CloseHandle(proc);

    size_t remaining = scanner.killRemaining();
    if (remaining > 0) {
        std::cerr << "WARNING: " << remaining << " of the related processes are not killed" << std::endl;
    }
    if (scanner.deleteDroppedFiles(session_timestamp) > 0) {
        if (params.noresp != t_noresp::NORESP_NO_RESTRICTION) {
            std::cerr << "WARNING: The session will remain active as long as the dropped files are not deleted!" << std::endl;
        }
    }
    save_remaing_files_report(session_timestamp, params, scanner);
    return ret_code;
}
