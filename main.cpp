#include <stdio.h>

#include <string>
#include <vector>
#include <iostream>
#include <sstream>

#include "hollows_hunter.h"
#include "process_util.h"

#define VERSION "0.1"

size_t kill_suspicious(std::vector<DWORD> &suspicious_pids)
{
    size_t killed = 0;
    std::vector<DWORD>::iterator itr;
    for (itr = suspicious_pids.begin(); itr != suspicious_pids.end(); itr++) {
        DWORD pid = *itr;
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess) {
            continue;
        }
        if (TerminateProcess(hProcess, 0)) {
            killed++;
        } else {
            std::cerr << "Could not terminate process. PID = " << pid << std::endl;
        }
        CloseHandle(hProcess);
    }
    return killed;
}

size_t deploy_scan(t_hh_params &hh_args)
{
    std::vector<DWORD> suspicious_pids;

    DWORD start_tick = GetTickCount();

    if (find_suspicious_process(suspicious_pids, hh_args) == 0) {
        return 0;
    }
    DWORD total_time = GetTickCount() - start_tick;
    std::cout << "--------" << std::endl;
    std::cout << "Finished scan in: " << std::dec << total_time << " milliseconds" << std::endl;

    if (hh_args.kill_suspicious) {
        kill_suspicious(suspicious_pids);
    }
    return suspicious_pids.size();
}

char* get_file_name(char *full_path)
{
    if (!full_path) return nullptr;

    size_t len = strlen(full_path);
    if (len < 2) {
        return full_path;
    }
    for (size_t i = len - 2; i > 0; i--) {
        if (full_path[i] == '\\' || full_path[i] == '/') {
            return full_path + (i + 1);
        }
    }
    return full_path;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cout << "args: <input exe>" << std::endl;
        system("pause");
        return 0;
    }

    DWORD flags = DETACHED_PROCESS | CREATE_NO_WINDOW;
    char* file_path = argv[1];
    std::cout << "Starting the process: " << file_path << std::endl;

    char* file_name = get_file_name(file_path);
    std::cout << "Exe name: " << file_name << std::endl;

    HANDLE proc = make_new_process(file_path, flags);
    if (!proc) {
        std::cerr << "Could not start the process!" << std::endl;
        return -1;
    }
 
    t_hh_params hh_args;
    hh_args_init(hh_args);
    hh_args.kill_suspicious = true;
    hh_args.loop_scanning = true;
    hh_args.pname = file_name;

    DWORD start_tick = GetTickCount();
    size_t count = 0;
    do {
        count++;
        size_t res = deploy_scan(hh_args);
        if (res > 0) {
            break;
        }
    } while (hh_args.loop_scanning);

    DWORD total_time = GetTickCount() - start_tick;
    std::cout << "Unpacked in: " << std::dec << total_time << " milliseconds; " << count << " attempts."  << std::endl;
    return 0;
}
