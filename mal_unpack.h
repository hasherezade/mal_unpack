#pragma once

#include <windows.h>

#include <Psapi.h>
#pragma comment(lib,"psapi.lib")

#include "pe_sieve_api.h"
#pragma comment(lib, "pe-sieve.lib")

#include <set>

class UnpackScanner
{
public:
    typedef struct {
        DWORD start_pid; // PID of the initial process
        std::string pname;
        bool loop_scanning;
        bool kill_suspicious;
        t_params pesieve_args; //PE-sieve parameters
    } t_unp_params;

    static void args_init(t_unp_params &args);

    UnpackScanner(t_unp_params &_unp_args)
        : unp_args(_unp_args),
        scanTime(0)
    {
    }

    size_t scan()
    {
        DWORD start_tick = GetTickCount();
        size_t found = this->_scan();
        this->scanTime = GetTickCount() - start_tick;
        return found;
    }

    void printStats();

    size_t killRemaining()
    {
        size_t remaining = kill_pids(children);
        remaining += kill_pids(unkilled_pids);
        return remaining;
    }

protected:
    static size_t kill_pids(std::set<DWORD> &pids);

    size_t _scan();
    bool isTarget(DWORD pid);

    t_unp_params &unp_args;

    //results:
    DWORD scanTime;
    std::set<DWORD> replaced;
    std::set<DWORD> unkilled_pids;
    std::set<DWORD> children;
};

