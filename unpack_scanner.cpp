#include "unpack_scanner.h"

#include <iostream>
#include <string>
#include <sstream>

#include "process_util.h"
#include "driver_comm.h"
#include "file_util.h"

#define WAIT_FOR_PROCESSES 100
#define MAX_ELEMENTS 1024
#define MAX_ATTEMPTS 10

void UnpackScanner::args_init(UnpackScanner::t_unp_params &unp_args)
{
    unp_args.pesieve_args = { 0 };

    unp_args.pesieve_args.quiet = true;
    unp_args.pesieve_args.no_hooks = true;
    unp_args.pesieve_args.make_reflection = false;
    unp_args.pesieve_args.imprec_mode = pesieve::PE_IMPREC_AUTO;
    unp_args.pesieve_args.data = pesieve::PE_DATA_SCAN_DOTNET;

    unp_args.loop_scanning = true;
    unp_args.module_path = L"";
    unp_args.is_main_module = true;
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

size_t UnpackScanner::collectByTheSameName(IN std::set<DWORD> allPids, IN std::map<DWORD, std::set<DWORD> >& parentToChildrenMap, OUT std::set<DWORD> &targets)
{
    const size_t startSize = targets.size();
    if (unp_args.module_path.length() == 0) {
        // the name is undefined, skip
        return 0;
    }
    
    std::set<DWORD>::iterator itr;
    for (itr = allPids.begin(); itr != allPids.end(); ++itr) {
        const DWORD pid = *itr;
        if (unp_args.is_main_module) {
            //std::wcout << "Searching by name: " << unp_args.module_path << "\n";
            const std::wstring process_name = get_process_module_path(pid);
            if (is_wanted_module(process_name.c_str(), unp_args.module_path.c_str())) {
                //std::wcout << "process_name:      " << process_name << "\n";
                //std::cout << "Match: " << pid << "\n";
                targets.insert(pid);
            }
        }
        else {
            //std::wcout << "Searching module in process: " << unp_args.module_path << "\n";
            if (is_module_in_process(pid, unp_args.module_path.c_str())) {
                targets.insert(pid);
            }
        }
    }
    // collect secondary targets: children of all other processes with matching name
    const size_t tree_depth = 100;
    for (size_t i = 0; i < tree_depth; i++) {
        size_t added_new = collectSecondaryTargets(targets, parentToChildrenMap, targets);
        if (added_new == 0) break;
    }
    return (targets.size() - startSize);
}

size_t UnpackScanner::killRemaining()
{
    kill_pids(allTargets);
    collectTargets();
    
    size_t remaining = kill_pids(allTargets);
    remaining += kill_pids(unkilled_pids);
    return remaining;
}

size_t UnpackScanner::collectDroppedFiles(ULONGLONG skipId)
{
    const size_t out_size = MAX_ELEMENTS;
    LONGLONG out_buffer[out_size + 1] = { 0 };
    bool isOK = driver::fetch_watched_files(this->unp_args.start_pid, out_buffer, out_size);
    if (isOK) {
        for (size_t i = 0; i < out_size; i++) {
            if (out_buffer[i] == 0) break;
            if (out_buffer[i] == skipId) continue;
            allDroppedFiles.insert(out_buffer[i]);
        }
    }
    return allDroppedFiles.size();
}

std::wstring filenames_to_string(const std::map<LONGLONG, std::wstring>&names)
{
    std::wstringstream ss;
    std::map<LONGLONG, std::wstring>::const_iterator itr;
    for (itr = names.begin(); itr != names.end(); ++itr) {
        ss << "File: " << itr->second << "\n";
    }
    return ss.str();
}

size_t UnpackScanner::deleteDroppedFiles(time_t session_time)
{
    const size_t all_files = allDroppedFiles.size();
    if (all_files == 0) {
        return 0; //nothing to deleteti
    }

    std::cout << "[INFO] Found dropped files:\n";
    std::map<LONGLONG, std::wstring> dos_names;
    file_util::file_ids_to_names(allDroppedFiles, dos_names, VOLUME_NAME_DOS);
    std::wcout << filenames_to_string(dos_names);
    const size_t all_names = dos_names.size();

    size_t remaining = all_names;
    DWORD attempts = 0;
    size_t deleted = 0;
    std::cout << "[INFO] Trying to delete in usermode...\n";

    for (attempts = 0; remaining && (attempts < MAX_ATTEMPTS); attempts++) {
        deleted += file_util::delete_dropped_files(dos_names, session_time, RENAMED_EXTENSION);
        remaining = all_names - deleted;
        if (remaining) {
#ifdef _DEBUG
            std::cerr << "[WARNING] Some dropped files are not deleted, retrying...\n";
#endif
            Sleep(WAIT_FOR_PROCESSES * attempts);
        }
    }
    std::cout << "[INFO] Deleted : " << std::dec << deleted << " (out of " << all_names << ") dropped files in " << attempts << " attempts\n";
    if (remaining) {
        std::cerr << "[WARNING] Not all dropped files are deleted. Failed:\n";
        std::wcerr << filenames_to_string(dos_names);
    }
    else {
        std::cout << "[OK] All dropped files are deleted!\n";
    }
    if (!remaining) {
        return 0;
    }
    std::cout << "[INFO] Trying to delete by the driver...\n";
    std::map<LONGLONG, std::wstring> nt_names;
    file_util::file_ids_to_names(allDroppedFiles, nt_names, VOLUME_NAME_NT);
    deleted += driver::delete_dropped_files_by_driver(nt_names, this->unp_args.start_pid);
    remaining = all_names - deleted;

    std::cout << "[INFO] Deleted : " << std::dec << deleted << " (out of " << all_names << ") dropped files in " << attempts << " attempts\n";
    if (remaining) {
        std::cerr << "[WARNING] Not all dropped files are deleted. Failed:\n";
        std::wcerr << filenames_to_string(nt_names);
    }
    else {
        std::cout << "[OK] All dropped files are deleted!\n";
    }
    return remaining;
}


size_t UnpackScanner::collectTargets()
{
    //populate the list as long as new processes are coming...
    size_t collected = -1;
    do {
        collected = _collectTargets();
        Sleep(WAIT_FOR_PROCESSES);
    } while (collected != 0);
    return collected;
}

size_t UnpackScanner::_collectTargets()
{
    const size_t out_size = MAX_ELEMENTS;
    DWORD out_buffer[out_size + 1] = { 0 };
    bool isOK = driver::fetch_watched_processes(this->unp_args.start_pid, out_buffer, out_size);
    if (isOK) {
        const size_t initial_size = allTargets.size();
        size_t found = 0;
        for (size_t i = 0; i < out_size; i++) {
            if (out_buffer[i] == 0) break;
            allTargets.insert(out_buffer[i]);
            found++;
        }
        return allTargets.size() - initial_size;
    }

    const size_t initial_size = allTargets.size();
    std::set<DWORD> mainTargets;
    static std::map<DWORD, std::set<DWORD> > parentToChildrenMap;
    std::set<DWORD> pids; //all running processes
    if (!_map_processes_parent_to_children(pids, parentToChildrenMap)) {
        std::cerr << "Mapping processes failed!\n";
    }

    // add the initial process to the targets:
    allTargets.insert(this->unp_args.start_pid);

    //collect children of the target: only for the starting PID
    std::set<DWORD> allChildren;
    allChildren.insert(this->unp_args.start_pid);
    const size_t tree_depth = 100;
    for (size_t i = 0; i < tree_depth; i++) {
        size_t added_new = collectSecondaryTargets(allChildren, parentToChildrenMap, allChildren);
#ifdef _DEBUG
        std::cout << "added new: " << added_new << "\n";
#endif
        if (added_new == 0) break;
    }
    allTargets.insert(allChildren.begin(), allChildren.end());

    //collecting by common name with the starting process:
    std::set<DWORD> byName;
    size_t added = collectByTheSameName(pids, parentToChildrenMap, byName);
    
    size_t targetsBefore = allTargets.size();
    allTargets.insert(byName.begin(), byName.end());
#ifdef _DEBUG
    std::cout << "Added by common name: " << (allTargets.size() - targetsBefore) << "\n";
#endif
    return allTargets.size() - initial_size;
}

size_t UnpackScanner::collectSecondaryTargets(IN std::set<DWORD> &_primaryTargets, IN std::map<DWORD, std::set<DWORD> >& parentToChildrenMap, OUT std::set<DWORD> &_secondaryTargets)
{
    size_t initial_size = _primaryTargets.size();

    std::set<DWORD>::const_iterator itr;
    for (itr = _primaryTargets.begin(); itr != _primaryTargets.end(); itr++) {
        DWORD pid = *itr;
#ifdef _DEBUG
        std::wcout << "Searching children of: " << pid << " [" << get_process_module_path(pid) << "]\n";
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
            std::wcout << "Child: " << child_pid << " [" << get_process_module_path(child_pid) << "]\n";
        }
#endif
    }
    return _primaryTargets.size() - initial_size;
}

ScanStats UnpackScanner::_scan()
{
    this->allTargets.clear();

    collectTargets();
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
