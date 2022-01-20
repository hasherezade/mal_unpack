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
#include "process_util.h"
#include "util.h"
#include "version.h"

#define WAIT_FOR_PROCESS_TIMEOUT 5000

#define VERSION VER_FILEVERSION_STR

void save_report(std::string file_name, ScanStats &finalStats)
{
    std::ofstream report;
    std::string report_name = "unpack.log";
    report.open(report_name, std::ofstream::out | std::ofstream::app);
    report << file_name << " : ";
    if (finalStats.detected) {
        report << "Unpacked in: " << std::dec << finalStats.scanTime << " milliseconds\n";
    }
    else {
        report << "Failed to unpack\n";
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
        std::cerr << "[*] Cache is Enabled!" << std::endl;
    }
    else {
        std::cerr << "[*] Cache is Disabled!" << std::endl;
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

    char* file_name = get_file_name(params.exe_path);
    std::cout << "Exe name: " << file_name << std::endl;

    DWORD timeout = params.timeout;
    std::string root_dir = std::string(file_name) + ".out";
    if (strlen(params.out_dir) > 0) {
        root_dir = std::string(params.out_dir) + "\\" + root_dir;
    }
    std::cout << "Root Dir: " << root_dir << "\n";

    t_pesieve_res ret_code = PESIEVE_ERROR;
    const DWORD flags = DETACHED_PROCESS | CREATE_NO_WINDOW;
    HANDLE proc = make_new_process(params.exe_path, params.exe_cmd, flags);
    if (!proc) {
        std::cerr << "Could not start the process!" << std::endl;
        return ret_code;
    }

    params.hh_args.pname = file_name;
    params.hh_args.start_pid = GetProcessId(proc);

    std::string out_dir = make_dir_name(root_dir, time(NULL));
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
    if (scanner.collectDroppedFiles()) {
        std::cout << "The process dropped some files!\n";
    }

    save_report(file_name, finalStats);

    if (is_unpacked) {
        std::cout << "Unpacked in: " << std::dec << finalStats.scanTime << " milliseconds; " << count << " attempts." << std::endl;
        ret_code = PESIEVE_DETECTED;
    }

    if (kill_pid(GetProcessId(proc))) {
        std::cout << "[OK] The initial process got killed." << std::endl;
    }
    CloseHandle(proc);
    size_t remaining = scanner.killRemaining();
    if (remaining > 0) {
        std::cout << "WARNING: " << remaining << " of the related processes are not killed" << std::endl;
    }
    
    return ret_code;
}
