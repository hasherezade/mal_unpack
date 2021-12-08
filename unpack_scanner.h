#pragma once

#include <windows.h>

#include <Psapi.h>
#pragma comment(lib,"psapi.lib")

#include "pe_sieve_api.h"
#pragma comment(lib, "pe-sieve.lib")

#include <iostream>
#include <set>
#include <map>

class ScanStats {
public:
    ScanStats()
        : scanned(0), detected(0)
    {
    }

    void printStats();

    DWORD scanTime;
    size_t scanned;
    size_t detected;
};

class UnpackScanner
{
public:
    typedef struct {
        DWORD start_pid; // PID of the initial process
        std::string pname;
        bool loop_scanning;
        bool kill_suspicious;
        pesieve::t_params pesieve_args; //PE-sieve parameters
    } t_unp_params;

    static void args_init(t_unp_params &args);

    UnpackScanner(t_unp_params &_unp_args)
        : unp_args(_unp_args)
    {
    }

    ScanStats scan()
    {
        DWORD start_tick = GetTickCount();
        ScanStats stats = this->_scan();
        stats.scanTime = GetTickCount() - start_tick;
        return stats;
    }

    void printStats();

    size_t collectDroppedFiles();

    size_t killRemaining();

    size_t deleteDroppedFiles();

protected:
    static size_t kill_pids(std::set<DWORD> &pids);

    ScanStats _scan();

    size_t collectTargets();
    size_t _collectTargets();


    size_t collectSecondaryTargets(IN std::set<DWORD> &_primaryTargets, IN std::map<DWORD, std::set<DWORD> > &_parentToChildrenMap, OUT std::set<DWORD> &_secondaryTargets);
    size_t collectByTheSameName(IN std::set<DWORD> allPids, IN std::map<DWORD, std::set<DWORD> >& _parentToChildrenMap, OUT std::set<DWORD> &targets);

    ScanStats scanProcesses(IN std::set<DWORD> pids);

    t_unp_params &unp_args;

    //results:
    std::set<DWORD> unkilled_pids;
    std::set<DWORD> allTargets;

    //IDs of the dropped files:
    std::set<LONGLONG> allDroppedFiles;
};

