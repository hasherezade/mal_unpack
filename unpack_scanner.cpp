#include "unpack_scanner.h"

#include <iostream>
#include <string.h>

#include "process_util.h"

void UnpackScanner::args_init(UnpackScanner::t_unp_params &unp_args)
{
    unp_args.pesieve_args = { 0 };

    unp_args.pesieve_args.quiet = true;
    unp_args.pesieve_args.modules_filter = 3;
    unp_args.pesieve_args.no_hooks = true;
    unp_args.pesieve_args.imp_rec = true;

    unp_args.loop_scanning = false;
    unp_args.pname = "";
}

//---

void ScanStats::printStats()
{
    std::cout << "--------" << std::endl;
    std::cout << "Finished scan in: " << std::dec << scanTime << " milliseconds, scanned: " << this->scanned << " unpacked: " << this->detected << std::endl;
}

//---

bool pesieve_scan(t_params args, ScanStats &stats)
{
    stats.scanned++;
    t_report report = PESieve_scan(args);
    if (report.errors) {
        return false;
    }
    if (report.implanted || report.replaced) {
        stats.detected++;
        std::cout << "Found potential payload: " << std::dec << args.pid << std::endl;
        return true;
    }
    return false;
}

bool get_process_name(IN HANDLE hProcess, OUT LPSTR nameBuf, IN DWORD nameMax)
{
    HMODULE hMod;
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        GetModuleBaseNameA(hProcess, hMod, nameBuf, nameMax);
        return true;
    }
    return false;
}

bool is_searched_process(DWORD processID, const char* searchedName)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == NULL) return false;

    CHAR szProcessName[MAX_PATH];
    if (get_process_name(hProcess, szProcessName, MAX_PATH)) {

        if (stricmp(szProcessName, searchedName) == 0) {
#ifdef _DEBUG
            printf("%s  (PID: %u)\n", szProcessName, processID);
#endif
            CloseHandle(hProcess);
            return true;
        }
    }
    CloseHandle(hProcess);
    return false;
}

bool UnpackScanner::isTarget(DWORD pid)
{
    //identify by PID:
    if (pid == this->unp_args.start_pid) {
        return true;
    }
    //follow also children:
    DWORD parent_pid = get_parent_pid(pid);
    if (parent_pid == this->unp_args.start_pid) {
        this->children.insert(pid);
        return true;
    }

    //identify by name:
    if (unp_args.pname.length() == 0) {
        //the name is undefined, skip
        return false;
    }
    if (is_searched_process(pid, unp_args.pname.c_str())) {
        return true;
    }
    return false;
}

ScanStats UnpackScanner::_scan()
{
    DWORD start_tick = GetTickCount();

    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return ScanStats();
    }

    ScanStats myStats;
    //calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);

    char image_buf[MAX_PATH] = { 0 };

    for (i = 0; i < cProcesses; i++) {
        if (aProcesses[i] == 0) continue;
        DWORD pid = aProcesses[i];
        if (!isTarget(pid)) {
            //it is not the searched process, so skip it
            continue;
        }

#ifdef _DEBUG
        std::cout << ">> Scanning PID: " << std::dec << pid << std::endl;
#endif
        unp_args.pesieve_args.pid = pid;
        if (pesieve_scan(unp_args.pesieve_args, myStats)) {
            replaced.insert(pid);
            bool is_killed = false;
            if (unp_args.kill_suspicious) {
                is_killed = kill_pid(pid);
            }
            if (!is_killed) {
                unkilled_pids.insert(pid);
            }
        }
    }
    return myStats;
}

size_t UnpackScanner::kill_pids(std::set<DWORD> &pids)
{
    size_t remaining = pids.size();
    std::set<DWORD>::iterator itr;
    for (itr = pids.begin(); itr != pids.end(); itr++) {
        DWORD pid = *itr;
        if (kill_till_dead_pid(pid)) {
            remaining--;
        }
    }
    return remaining;
}
