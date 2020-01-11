#pragma once

#include <paramkit.h>

using namespace paramkit;

#define DEFAULT_TIMEOUT 1000

#define PARAM_EXE "exe"
#define PARAM_TIMEOUT "timeout"
#define PARAM_OUT_DIR "dir"


typedef struct {
    char exe_path[MAX_PATH];
    char out_dir[MAX_PATH];
    DWORD timeout;
} t_params_struct;

class UnpackParams : public Params
{
public:
    UnpackParams()
        : Params()
    {
        this->addParam(new StringParam(PARAM_EXE, true));
        this->setInfo(PARAM_EXE, "Input exe (to be run)");

        this->addParam(new IntParam(PARAM_TIMEOUT, false));
        this->setIntValue(PARAM_TIMEOUT, DEFAULT_TIMEOUT);
        this->setInfo(PARAM_TIMEOUT, "Timeout: ms");

        this->addParam(new StringParam(PARAM_OUT_DIR, false));
        this->setInfo(PARAM_OUT_DIR, "Output directory");
    }

    void fillStruct(t_params_struct &ps)
    {
        StringParam *myExe = dynamic_cast<StringParam*>(this->getParam(PARAM_EXE));
        if (myExe) {
            myExe->copyToCStr(ps.exe_path, sizeof(ps.exe_path));
        }
        StringParam *myDir = dynamic_cast<StringParam*>(this->getParam(PARAM_OUT_DIR));
        if (myDir) {
            myDir->copyToCStr(ps.out_dir, sizeof(ps.out_dir));
        }
        IntParam *myTimeout = dynamic_cast<IntParam*>(this->getParam(PARAM_TIMEOUT));
        if (myTimeout) ps.timeout = myTimeout->value;
    }
};
