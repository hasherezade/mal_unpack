#include "rm_util.h"
#include <iostream>

//---

bool RmSessionManager::populate(LPCWSTR rgsFiles[], DWORD filesCount)
{
    if (rgAffectedApps) {
        return false; // already populated
    }
    if (!isInit) init(); // autoinit
    if (!dwSessionHandle || dwSessionHandle == (DWORD)INVALID_HANDLE_VALUE) {
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
    RM_PROCESS_INFO* rgAffectedApps = NULL;
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
