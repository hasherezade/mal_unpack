#include "unpack_scanner.h"

#include <iostream>
#include <string.h>

#include "process_util.h"

#define WAIT_FOR_PROCESSES 100

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
    if (report.suspicious) {
        stats.detected++;
        std::cout << "Found suspicious: " << std::dec << args.pid << std::endl;
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

size_t UnpackScanner::collectByTheSameName(IN std::set<DWORD> allPids, OUT std::set<DWORD> &targets)
{
    const size_t startSize = targets.size();
    if (unp_args.pname.length() == 0) {
        // the name is undefined, skip
        return 0;
    }
    std::set<DWORD>::iterator itr;
    for (itr = allPids.begin(); itr != allPids.end(); ++itr) {
        const DWORD pid = *itr;
        if (is_searched_process(pid, unp_args.pname.c_str())) {
            targets.insert(pid);
        }
    }
    // collect secondary targets: children of all other processes with matching name
    const size_t tree_depth = 100;
    for (size_t i = 0; i < tree_depth; i++) {
        size_t added_new = collectSecondaryTargets(targets, targets);
        if (added_new == 0) break;
    }
    return (targets.size() - startSize);
}

size_t UnpackScanner::collectTargets()
{
    const size_t initial_size = allTargets.size();
    std::set<DWORD> mainTargets;

    std::set<DWORD> pids; //all running processes
    if (!map_processes_parent_to_children(pids, this->parentToChildrenMap)) {
        std::cerr << "Mapping processes failed!\n";
    }

    // add the initial process to the targets:
    allTargets.insert(this->unp_args.start_pid);

    //collect children of the target: only for the starting PID
    std::set<DWORD> allChildren;
    allChildren.insert(this->unp_args.start_pid);
    const size_t tree_depth = 100;
    for (size_t i = 0; i < tree_depth; i++) {
        size_t added_new = collectSecondaryTargets(allChildren, allChildren);
#ifdef _DEBUG
        std::cout << "added new: " << added_new << "\n";
#endif
        if (added_new == 0) break;
    }
    allTargets.insert(allChildren.begin(), allChildren.end());

    //collecting by common name with the starting process:
    std::set<DWORD> byName;
    size_t added = collectByTheSameName(pids, byName);
    
    size_t targetsBefore = allTargets.size();
    allTargets.insert(byName.begin(), byName.end());
#ifdef _DEBUG
    std::cout << "Added by common name: " << (allTargets.size() - targetsBefore) << "\n";
#endif
    return allTargets.size() - initial_size;
}

size_t UnpackScanner::collectSecondaryTargets(IN std::set<DWORD> &_primaryTargets, OUT std::set<DWORD> &_secondaryTargets)
{
    size_t initial_size = _primaryTargets.size();

    std::set<DWORD>::const_iterator itr;
    for (itr = _primaryTargets.begin(); itr != _primaryTargets.end(); itr++) {
        DWORD pid = *itr;
#ifdef _DEBUG
        std::cout << "Searching children of: " << pid << " [" << get_process_name_str(pid) << "]\n";
#endif
        std::map<DWORD, std::set<DWORD> >::iterator child_itr = parentToChildrenMap.find(pid);
        if (child_itr == parentToChildrenMap.end()) {
            //std::cout << "children not found!\n";
            continue;
        }
        
        std::set<DWORD> &childrenList = child_itr->second;
        // add all the children on the process to the targets:
        _secondaryTargets.insert(childrenList.begin(), childrenList.end());

#ifdef _DEBUG
        std::cout << std::dec << pid << " >>>>> Adding " << childrenList.size() << " children of : " << pid << " to targets list\n";
        std::set<DWORD>::iterator itr;
        for (itr = childrenList.begin(); itr != childrenList.end(); itr++) {
            DWORD child_pid = *itr;
            std::cout << "Child: " << child_pid << " [" << get_process_name_str(child_pid) << "]\n";
        }
#endif
    }
    return _primaryTargets.size() - initial_size;
}

ScanStats UnpackScanner::_scan()
{
    this->allTargets.clear();

    //populate the list as long as new processes are coming...
    size_t collected = -1;
    do {
        collected = collectTargets();
        Sleep(WAIT_FOR_PROCESSES);
    } while (collected != 0);

    return scanProcesses(allTargets);
}

size_t UnpackScanner::kill_pids(IN std::set<DWORD> &pids)
{
    size_t remaining = pids.size();
    std::set<DWORD>::iterator itr;
    for (itr = pids.begin(); itr != pids.end(); itr++) {
        DWORD pid = *itr;
        if (kill_pid(pid)) {
            remaining--;
        }
    }
    return remaining;
}
