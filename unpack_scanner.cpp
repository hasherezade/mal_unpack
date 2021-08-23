#include "unpack_scanner.h"

#include <iostream>
#include <string.h>

#include "process_util.h"

void UnpackScanner::args_init(UnpackScanner::t_unp_params &unp_args)
{
    unp_args.pesieve_args = { 0 };

    unp_args.pesieve_args.quiet = true;
    unp_args.pesieve_args.no_hooks = true;
    unp_args.pesieve_args.make_reflection = true;
    unp_args.pesieve_args.imprec_mode = pesieve::PE_IMPREC_AUTO;

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

bool pesieve_scan(pesieve::t_params args, ScanStats &stats)
{
    stats.scanned++;
    pesieve::t_report report = PESieve_scan(args);
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

        if (_stricmp(szProcessName, searchedName) == 0) {
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

bool UnpackScanner::isTarget(IN DWORD pid)
{
    //identify by PID:
    if (pid == this->unp_args.start_pid) {
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

ScanStats UnpackScanner::scanProcesses(IN std::set<DWORD> pids)
{
    size_t i = 0;
    ScanStats myStats;

    std::set<DWORD>::iterator pid_itr;
    for (pid_itr = pids.begin(); pid_itr != pids.end(); pid_itr++) {

        const DWORD pid = *pid_itr;
        if (pid == 0) continue;
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

size_t UnpackScanner::collectTargets()
{
    const size_t initial_size = allTargets.size();

    DWORD aProcesses[1024], cbNeeded;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return 0;
    }
    
    std::set<DWORD> mainTargets;

    //calculate how many process identifiers were returned.
    size_t cProcesses = cbNeeded / sizeof(DWORD);
    char image_buf[MAX_PATH] = { 0 };

    for (size_t i = 0; i < cProcesses; i++) {
        if (aProcesses[i] == 0) continue;

        const DWORD pid = aProcesses[i];
        const DWORD parent = get_parent_pid(pid);

        if (parent != INVALID_PID_VALUE) {\
            parentToChildrenMap[parent].insert(pid);
        }

        if (!isTarget(pid)) {
            //it is not the searched process, so skip it
            continue;
        }
        //std::cout << ">>>>> Adding PID : " << std::dec << pid << " to targets list "<< "\n";
        allTargets.insert(pid);
        mainTargets.insert(pid);
    }

    //collect children of the target: only for the starting PID
    startingPidTree.insert(this->unp_args.start_pid);
    const size_t tree_depth = 5;
    for (size_t i = 0; i < tree_depth; i++) {
        size_t added_new = collectSecondaryTargets(startingPidTree);
        //std::cout << "added new: " << added_new << "\n";
    }

    //collect secondary targets: children of all other processes with matching name
    for (size_t i = 0; i < tree_depth; i++) {
        size_t added_new = collectSecondaryTargets(mainTargets);
        //std::cout << "added new: " << added_new << "\n";
    }
    return allTargets.size() - initial_size;
}

size_t UnpackScanner::collectSecondaryTargets(IN std::set<DWORD> &_primaryTargets)
{
    size_t initial_size = _primaryTargets.size();

    std::set<DWORD>::const_iterator itr;
    for (itr = _primaryTargets.begin(); itr != _primaryTargets.end(); itr++) {
        DWORD pid = *itr;
        //std::cout << "Searching chldren of: " << pid << "\n";
        std::map<DWORD, std::set<DWORD> >::iterator child_itr = parentToChildrenMap.find(pid);
        if (child_itr == parentToChildrenMap.end()) {
            //std::cout << "children not found!\n";
            continue;
        }
        std::set<DWORD> &childrenList = child_itr->second;

        allTargets.insert(childrenList.begin(), childrenList.end());
        _primaryTargets.insert(childrenList.begin(), childrenList.end());
#ifdef _DEBUG
        std::cout << std::dec << pid << " >>>>> Adding " << childrenList.size() << " children of : " << pid << " to targets list\n";
        std::set<DWORD>::iterator itr;
        for (itr = childrenList.begin(); itr != childrenList.end(); itr++) {
            std::cout << "Child: " << *itr << "\n";
        }
#endif
    }
    return _primaryTargets.size() - initial_size;
}

ScanStats UnpackScanner::_scan()
{
    this->parentToChildrenMap.clear();
    this->allTargets.clear();
    this->startingPidTree.clear();

    size_t collected = -1;
    do {
        collected = collectTargets();
        Sleep(100);
    }
     while (collected != 0);

    return scanProcesses(allTargets);
}

size_t UnpackScanner::kill_pids(IN std::set<DWORD> &pids)
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
