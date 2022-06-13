#pragma once

#include <windows.h>
#include <restartmanager.h>
#include <iostream>

#pragma comment(lib, "rstrtmgr.lib")

#define INVALID_HANDLE_VALUE_DW (-1)

struct RmSessionManager
{
public:
    RmSessionManager()
    {
    }

    ~RmSessionManager()
    {
        destroy();
    }

    bool init()
    {
        if (isInit) {
            return true;
        }
        if (RmStartSession(&dwSessionHandle, 0, sessKey) != ERROR_SUCCESS) {
            return false;
        }
        isInit = true;
        return true;
    }

    bool populate(LPCWSTR rgsFiles[], DWORD filesCount);

    void printList()
    {
        if (!rgAffectedApps) return;

        for (DWORD i = 0; i < nAffectedApps; ++i) {
            RM_PROCESS_INFO app = rgAffectedApps[i];
            std::wcout << "[*] Blocking app: " << app.strAppName << "\n";
        }
    }

    bool shutdownApps()
    {
        DWORD res = RmShutdown(dwSessionHandle, RmForceShutdown, NULL);
        if (ERROR_SUCCESS != res)
        {
#ifdef _DEBUG
            std::cout << "shutdownApps failed: " << std::hex << res << "\n";
#endif
            bool isOk = killAllApps();
#ifdef _DEBUG
            std::cout << "kill apps result: " << isOk << "\n";
#endif
            return isOk;
        }
        return true;
    }

    bool killAllApps();

    bool restartApps()
    {
        if (ERROR_SUCCESS != RmRestart(dwSessionHandle, 0, NULL))
        {
            return false;
        }
        return true;
    }

    void destroy()
    {
        if (rgAffectedApps) {
            delete[] rgAffectedApps; rgAffectedApps = NULL;
        }
        nAffectedApps = 0;
        if (dwSessionHandle != INVALID_HANDLE_VALUE_DW) {
            RmEndSession(dwSessionHandle);
        }
    }
    
    UINT countAffectedApps()
    {
        return nAffectedApps;
    }

protected:
    bool isInit = false;

    DWORD dwSessionHandle = INVALID_HANDLE_VALUE_DW;

    UINT nAffectedApps = 0;
    RM_PROCESS_INFO* rgAffectedApps = NULL;
    WCHAR sessKey[CCH_RM_SESSION_KEY + 1] = { 0 };
};
