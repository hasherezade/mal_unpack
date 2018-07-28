#pragma once

#include <windows.h>

#include <Psapi.h>
#pragma comment(lib,"psapi.lib")

#include "pe_sieve_api.h"
#pragma comment(lib, "pe-sieve.lib")

class UnpackScanner
{
public:
    typedef struct {
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

protected:
    size_t _scan();

    t_unp_params &unp_args;

    //results:
    DWORD scanTime;
    std::vector<DWORD> replaced;
    std::vector<DWORD> unkilled_pids;
};


