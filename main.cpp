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

#include "unpack_scanner.h"
#include "process_util.h"
#include "util.h"

#define WAIT_FOR_PROCESS_TIMEOUT 5000

#define VERSION "0.3-a"

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

int main(int argc, char *argv[])
{
    UnpackParams uParams;
    t_params_struct params = { 0 };

    if (argc < 2) {
        std::cout << "mal_unpack " << VERSION;
        
#ifdef _WIN64
        std::cout << " (x64)" << "\n";
#else
        std::cout << " (x86)" << "\n";
#endif
        std::cout << "Dynamic malware unpacker\n";
        std::cout << "Built on: " << __DATE__ << "\n";
        DWORD pesieve_ver = PESieve_version();
        std::cout << "using: PE-sieve v." << version_to_str(pesieve_ver) << "\n\n";

        print_in_color(0xc, "CAUTION: Supplied malware will be deployed! Use it on a VM only!\n");
        std::cout << "Args:\n\n";
        uParams.info();
        system("pause");
        return 0;
    }
    if (!uParams.parse(argc, argv) || !uParams.hasRequiredFilled()) {
        uParams.info();
        return 0;
    }

    uParams.fillStruct(params);

    DWORD flags = DETACHED_PROCESS | CREATE_NO_WINDOW;
    char* file_path = params.exe_path;
    std::cout << "Starting the process: " << file_path << std::endl;

    char* file_name = get_file_name(file_path);
    std::cout << "Exe name: " << file_name << std::endl;

    DWORD timeout = params.timeout;
    std::string root_dir = std::string(file_name) + ".out";
    if (strlen(params.out_dir) > 0) {
        root_dir = std::string(params.out_dir) + "\\" + root_dir;
    }
    std::cout << "Root Dir: " << root_dir << "\n";

    HANDLE proc = make_new_process(file_path, flags);
    if (!proc) {
        std::cerr << "Could not start the process!" << std::endl;
        return -1;
    }

    UnpackScanner::t_unp_params hh_args;
    UnpackScanner::args_init(hh_args);

    hh_args.kill_suspicious = true;
    hh_args.loop_scanning = true;
    hh_args.pname = file_name;
    hh_args.start_pid = GetProcessId(proc);
    
    std::string out_dir = make_dir_name(root_dir, time(NULL));
    set_output_dir(hh_args.pesieve_args, out_dir.c_str());

    DWORD start_tick = GetTickCount();
    size_t count = 0;

    DWORD ret_code = ERROR_INVALID_PARAMETER;
    bool is_unpacked = false;
    UnpackScanner scanner(hh_args);
    ScanStats finalStats;
    do {
        DWORD curr_time = GetTickCount() - start_tick;
        if ((timeout != -1 && timeout > 0) && curr_time > timeout) {
            std::cout << "Unpack timeout passed!" << std::endl;
            ret_code = WAIT_TIMEOUT;
            break;
        }
        count++;
        
        ScanStats stats = scanner.scan();
        
        if (stats.scanned == 0) {
            if (curr_time < WAIT_FOR_PROCESS_TIMEOUT) {
                std::cout << "Nothing to scan... Waiting for a process: " << (WAIT_FOR_PROCESS_TIMEOUT - curr_time) << "ms\n";
            }
            else {
                std::cout << "Waiting timeout passed!" << std::endl;
                ret_code = WAIT_TIMEOUT;
                break;
            }
        }
        if (stats.detected > 0) {
            finalStats.detected++;
            is_unpacked = true;
            ret_code = ERROR_SUCCESS;
            break;
        }
    } while (hh_args.loop_scanning);

    finalStats.scanTime = GetTickCount() - start_tick;
    save_report(file_name, finalStats);

    if (is_unpacked) {
        std::cout << "Unpacked in: " << std::dec << finalStats.scanTime << " milliseconds; " << count << " attempts." << std::endl;
    }
    if (kill_till_dead(proc)) {
        std::cout << "[OK] The initial process got killed." << std::endl;
    }
    CloseHandle(proc);
    size_t remaining = scanner.killRemaining();
    if (remaining > 0) {
        std::cout << "WARNING: " << remaining << " of the related processes are not killed" << std::endl;
    }
    return ret_code;
}
