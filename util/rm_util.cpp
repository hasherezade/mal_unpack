#include "rm_util.h"
#include "process_util.h"
#include <iostream>

//---

bool RmSessionManager::populate(LPCWSTR rgsFiles[], DWORD filesCount)
{
    if (rgAffectedApps) {
        return false; // already populated
    }
    if (!isInit) init(); // autoinit
    if (dwSessionHandle == INVALID_HANDLE_VALUE_DW) {
        return false; // not initialized
    }

    DWORD res = RmRegisterResources(dwSessionHandle,
        filesCount,
        rgsFiles,       // Files
        0,
        NULL,           // Processes
        0,
        NULL);          // Services 

    if (res != ERROR_SUCCESS) {
        return false;
    }

    bool isSuccess = false;
    UINT nRetry = 0;

    UINT nProcInfoNeeded = 0;
    RM_REBOOT_REASON dwRebootReasons = RmRebootReasonNone;
    DWORD dwErrCode = ERROR_SUCCESS;
    do
    {
        dwErrCode = RmGetList(dwSessionHandle,
            &nProcInfoNeeded,
            &nAffectedApps,
            rgAffectedApps,
            (LPDWORD)&dwRebootReasons);

        if (ERROR_SUCCESS == dwErrCode)
        {
            //
            // RmGetList() succeeded
            //
            isSuccess = true;
            break;
        }

        if (ERROR_MORE_DATA != dwErrCode)
        {
            //
            // RmGetList() failed, with errors 
            // other than ERROR_MORE_DATA
            //
            break;
        }

        //
        // RmGetList() is asking for more data
        //
        nAffectedApps = nProcInfoNeeded;

        if (NULL != rgAffectedApps)
        {
            delete[]rgAffectedApps;
            rgAffectedApps = NULL;
        }

        rgAffectedApps = new RM_PROCESS_INFO[nAffectedApps];
    } while ((ERROR_MORE_DATA == dwErrCode) && (nRetry++ < 3));

    return isSuccess;
}


bool RmSessionManager::killAllApps()
{
    if (!rgAffectedApps) return true;

    size_t killed = 0;
    for (DWORD i = 0; i < nAffectedApps; ++i) {
        RM_PROCESS_INFO app = rgAffectedApps[i];
        if (kill_pid(app.Process.dwProcessId)) killed++;
    }
    return (killed == nAffectedApps);
}
