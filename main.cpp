#include <stdio.h>

#include <string>
#include <vector>
#include <iostream>
#include <sstream>

#include "hollows_hunter.h"
#include "process_util.h"

#define VERSION "0.1"

size_t deploy_scan(t_hh_params &hh_args)
{
    std::vector<DWORD> suspicious_pids;
    std::vector<DWORD> unkilled_pids;

    DWORD start_tick = GetTickCount();
    if (find_suspicious_process(suspicious_pids, unkilled_pids, hh_args) == 0) {
        return 0;
    }
    DWORD total_time = GetTickCount() - start_tick;
    std::cout << "--------" << std::endl;
    std::cout << "Finished scan in: " << std::dec << total_time << " milliseconds" << std::endl;
    if ((suspicious_pids.size() > 0) && unkilled_pids.size()) {
        std::cout << "WARNING: " << unkilled_pids.size() << " of the suspicious processes are not killed" << std::endl;
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

bool kill_till_dead(HANDLE &proc)
{
    bool is_killed = false;
    //terminate the original process (if not terminated yet)
    DWORD exit_code = 0;
    do {
        GetExitCodeProcess(proc, &exit_code);
        if (exit_code == STILL_ACTIVE) {
            TerminateProcess(proc, 0);
        }
        else {
            is_killed = true;
            break;
        }
    } while (true);
    return is_killed;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cout << "args: <input exe> [timeout: ms]" << std::endl;
        system("pause");
        return 0;
    }

    DWORD flags = DETACHED_PROCESS | CREATE_NO_WINDOW;
    char* file_path = argv[1];
    std::cout << "Starting the process: " << file_path << std::endl;

    char* file_name = get_file_name(file_path);
    std::cout << "Exe name: " << file_name << std::endl;

    DWORD timeout = (-1); //INFINITE
    if (argc >= 3) {
        timeout = atol(argv[2]);
    }

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

    DWORD ret_code = ERROR_INVALID_PARAMETER;
    bool is_unpacked = false;
    do {
        DWORD curr_time = GetTickCount() - start_tick;
        if ((timeout != -1 && timeout > 0) && curr_time > timeout) {
            std::cout << "Timeout passed!" << std::endl;
            ret_code = WAIT_TIMEOUT;
            break;
        }
        count++;
        size_t res = deploy_scan(hh_args);
        if (res > 0) {
            is_unpacked = true;
            ret_code = ERROR_SUCCESS;
            break;
        }
    } while (hh_args.loop_scanning);

    if (is_unpacked) {
        DWORD total_time = GetTickCount() - start_tick;
        std::cout << "Unpacked in: " << std::dec << total_time << " milliseconds; " << count << " attempts." << std::endl;
    }
    if (kill_till_dead(proc)) {
        std::cout << "[OK] The initial process got killed." << std::endl;
    }
    CloseHandle(proc);
    return ret_code;
}
