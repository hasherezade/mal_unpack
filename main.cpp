#include <stdio.h>
#include <time.h>

#include <string>
#include <vector>
#include <iostream>
#include <sstream>

#include "unpack_scanner.h"
#include "process_util.h"

#define DEFAULT_TIMEOUT 1000

#define VERSION "0.2-b"

std::string version_to_str(DWORD version)
{
    BYTE *chunks = (BYTE*) &version;
    std::stringstream stream;
    stream << std::hex <<
        (int)chunks[3] << "." <<
        (int)chunks[2] << "." <<
        (int)chunks[1] << "." <<
        (int)chunks[0];

    return stream.str();
}

std::string make_dir_name(std::string baseDir, std::string filename, time_t timestamp)
{
    std::stringstream stream;
    if (baseDir.length() > 0) {
        stream << baseDir;
        stream << "\\";
    }
    stream << filename << "_";
    stream << "scan_";
    stream << timestamp;
    return stream.str();
}

bool set_output_dir(t_params &args, const char *new_dir)
{
    if (!new_dir) return false;

    size_t new_len = strlen(new_dir);
    size_t buffer_len = sizeof(args.output_dir);
    if (new_len > buffer_len) return false;

    memset(args.output_dir, 0, buffer_len);
    memcpy(args.output_dir, new_dir, new_len);
    return true;
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
        std::cout << "mal_unpack " << VERSION << std::endl;
        std::cout << "Dynamic malware unpacker\n";
        DWORD pesieve_ver = PESieve_version();
        std::cout << "using: PE-sieve v." << version_to_str(pesieve_ver) << "\n";
        std::cout << "CAUTION: Supplied malware will be deployed! Use it on a VM only!\n" << std::endl;
        std::cout << "args: <input exe> [timeout: ms, default "<< DEFAULT_TIMEOUT <<" ms]" << std::endl;
        system("pause");
        return 0;
    }

    DWORD flags = DETACHED_PROCESS | CREATE_NO_WINDOW;
    char* file_path = argv[1];
    std::cout << "Starting the process: " << file_path << std::endl;

    char* file_name = get_file_name(file_path);
    std::cout << "Exe name: " << file_name << std::endl;

    DWORD timeout = DEFAULT_TIMEOUT;
    if (argc >= 3) {
        timeout = atol(argv[2]);
    }

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
    
    std::string out_dir = make_dir_name("", file_name, time(NULL));
    set_output_dir(hh_args.pesieve_args, out_dir.c_str());

    DWORD start_tick = GetTickCount();
    size_t count = 0;

    DWORD ret_code = ERROR_INVALID_PARAMETER;
    bool is_unpacked = false;
    UnpackScanner scanner(hh_args);

    do {
        DWORD curr_time = GetTickCount() - start_tick;
        if ((timeout != -1 && timeout > 0) && curr_time > timeout) {
            std::cout << "Timeout passed!" << std::endl;
            ret_code = WAIT_TIMEOUT;
            break;
        }
        count++;
        
        ScanStats stats = scanner.scan();
        stats.printStats();

        if (stats.detected > 0) {
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
    size_t remaining = scanner.killRemaining();
    if (remaining > 0) {
        std::cout << "WARNING: " << remaining << " of the related processes are not killed" << std::endl;
    }
    return ret_code;
}
