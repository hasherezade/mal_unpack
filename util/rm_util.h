#pragma once

#include <windows.h>
#include <restartmanager.h>
#include <iostream>

#pragma comment(lib, "rstrtmgr.lib")

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
        for (DWORD i = 0; i < nAffectedApps; ++i) {
            RM_PROCESS_INFO app = rgAffectedApps[i];
            std::cout << "Blocking app: " << app.strAppName << "\n";
        }
    }

    bool shutdownApps()
    {
        if (ERROR_SUCCESS != RmShutdown(dwSessionHandle, 0, NULL))
        {
            return false;
        }
        return true;
    }

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
        if (dwSessionHandle && dwSessionHandle != (DWORD)INVALID_HANDLE_VALUE) {
            RmEndSession(dwSessionHandle);
        }
    }

protected:
    bool isInit = false;

    WCHAR sessKey[CCH_RM_SESSION_KEY + 1] = { 0 };
    DWORD dwSessionHandle = (DWORD)INVALID_HANDLE_VALUE;

    UINT nAffectedApps = 0;
    RM_PROCESS_INFO* rgAffectedApps = NULL;
};
