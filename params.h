#pragma once

#include <paramkit.h>
using namespace paramkit;

#include "unpack_scanner.h"

#define DEFAULT_TIMEOUT 1000

#define PARAM_EXE "exe"
#define PARAM_CMD "cmd"
#define PARAM_TIMEOUT "timeout"
#define PARAM_OUT_DIR "dir"

#define PARAM_DATA "data"
#define PARAM_MINDUMP "minidmp"
#define PARAM_SHELLCODE "shellc"
#define PARAM_HOOKS "hooks"
#define PARAM_IMP "imp"
#define PARAM_TRIGGER "trigger"

typedef enum {
    TRIG_TIMEOUT = 0,
    TRIG_ANY = 1 ,
    COUNT_TRIG
} t_term_trigger;

typedef struct {
    char exe_path[MAX_PATH];
    char exe_cmd[MAX_PATH];
    char out_dir[MAX_PATH];
    DWORD timeout;
    t_term_trigger trigger;
    UnpackScanner::t_unp_params hh_args;
} t_params_struct;

class UnpackParams : public Params
{
public:
    UnpackParams()
        : Params()
    {
        this->addParam(new StringParam(PARAM_EXE, true));
        this->setInfo(PARAM_EXE, "Input exe (to be run)");

        this->addParam(new StringParam(PARAM_CMD, false));
        this->setInfo(PARAM_CMD, "Commandline arguments for the input exe");

        this->addParam(new IntParam(PARAM_TIMEOUT, true));
        this->setInfo(PARAM_TIMEOUT, "Timeout: ms");

        this->addParam(new StringParam(PARAM_OUT_DIR, false));
        this->setInfo(PARAM_OUT_DIR, "Output directory");

        EnumParam *dataParam = new EnumParam(PARAM_DATA, "data_scan_mode", false);
        if (dataParam) {
            this->addParam(dataParam);
            this->setInfo(PARAM_DATA, "Set if non-executable pages should be scanned");
            dataParam->addEnumValue(pesieve::t_data_scan_mode::PE_DATA_NO_SCAN, "none: do not scan non-executable pages");
            dataParam->addEnumValue(pesieve::t_data_scan_mode::PE_DATA_SCAN_DOTNET, ".NET: scan non-executable in .NET applications");
            dataParam->addEnumValue(pesieve::t_data_scan_mode::PE_DATA_SCAN_NO_DEP, "if no DEP: scan non-exec if DEP is disabled (or if is .NET)");
            dataParam->addEnumValue(pesieve::t_data_scan_mode::PE_DATA_SCAN_ALWAYS, "always: scan non-executable pages unconditionally");
        }

        

        this->addParam(new BoolParam(PARAM_MINDUMP, false));
        this->setInfo(PARAM_MINDUMP, "Create a minidump of the detected process");

        this->addParam(new BoolParam(PARAM_SHELLCODE, false));
        this->setInfo(PARAM_SHELLCODE, "Detect shellcodes");

        this->addParam(new BoolParam(PARAM_HOOKS, false));
        this->setInfo(PARAM_HOOKS, "Detect hooks and patches");

        EnumParam *triggerParam = new EnumParam(PARAM_TRIGGER, "term_trigger", false);
        if (triggerParam) {
            this->addParam(triggerParam);
            this->setInfo(PARAM_TRIGGER, "a trigger causing unpacker to terminate");
            triggerParam->addEnumValue(t_term_trigger::TRIG_TIMEOUT, "T", "on timeout ONLY (no matter detected content)");
            triggerParam->addEnumValue(t_term_trigger::TRIG_ANY, "A", "if any suspicious indicator detected [DEFAULT]");
        }

        EnumParam *impParam = new EnumParam(PARAM_IMP, "imp_rec", false);
        if (impParam) {
            this->addParam(impParam);
            this->setInfo(PARAM_IMP, "in which mode ImportTable should be recovered");
            impParam->addEnumValue(pesieve::t_imprec_mode::PE_IMPREC_AUTO, "A", "try to autodetect the most suitable mode [DEFAULT]");
            impParam->addEnumValue(pesieve::t_imprec_mode::PE_IMPREC_UNERASE, "U", "unrase the erased parts of partialy damaged ImportTable");
            impParam->addEnumValue(pesieve::t_imprec_mode::PE_IMPREC_REBUILD, "R", "rebuild ImportTable from scratch");
        }

        //optional: group parameters
        std::string str_group = "output options";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_OUT_DIR, str_group);

        str_group = "scan options";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_DATA, str_group);
        this->addParamToGroup(PARAM_SHELLCODE, str_group);
        this->addParamToGroup(PARAM_HOOKS, str_group);

        str_group = "dump options";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_MINDUMP, str_group);
        this->addParamToGroup(PARAM_IMP, str_group);
    }

    void fillStruct(t_params_struct &ps)
    {
        StringParam *myExe = dynamic_cast<StringParam*>(this->getParam(PARAM_EXE));
        if (myExe) {
            myExe->copyToCStr(ps.exe_path, sizeof(ps.exe_path));
        }
        StringParam *myCmd = dynamic_cast<StringParam*>(this->getParam(PARAM_CMD));
        if (myCmd) {
            myCmd->copyToCStr(ps.exe_cmd, sizeof(ps.exe_cmd));
        }
        StringParam *myDir = dynamic_cast<StringParam*>(this->getParam(PARAM_OUT_DIR));
        if (myDir) {
            myDir->copyToCStr(ps.out_dir, sizeof(ps.out_dir));
        }
        IntParam *myTimeout = dynamic_cast<IntParam*>(this->getParam(PARAM_TIMEOUT));
        if (myTimeout) ps.timeout = myTimeout->value;

        EnumParam *myData = dynamic_cast<EnumParam*>(this->getParam(PARAM_DATA));
        if (myData && myData->isSet()) {
            ps.hh_args.pesieve_args.data = (pesieve::t_data_scan_mode) myData->value;
        }
        EnumParam *myTrigger = dynamic_cast<EnumParam*>(this->getParam(PARAM_TRIGGER));
        if (myTrigger && myTrigger->isSet()) {
            ps.trigger = (t_term_trigger) myTrigger->value;
        }
        BoolParam *myMinidump = dynamic_cast<BoolParam*>(this->getParam(PARAM_MINDUMP));
        if (myMinidump && myMinidump->isSet()) {
            ps.hh_args.pesieve_args.minidump = myMinidump->value;
        }
        BoolParam *myShellc = dynamic_cast<BoolParam*>(this->getParam(PARAM_SHELLCODE));
        if (myShellc && myShellc->isSet()) {
            ps.hh_args.pesieve_args.shellcode = myShellc->value;
        }
        BoolParam *myHooks = dynamic_cast<BoolParam*>(this->getParam(PARAM_HOOKS));
        if (myHooks && myHooks->isSet()) {
            ps.hh_args.pesieve_args.no_hooks = !(myHooks->value);
        }
        EnumParam *myImp = dynamic_cast<EnumParam*>(this->getParam(PARAM_IMP));
        if (myImp && myImp->isSet()) {
            ps.hh_args.pesieve_args.imprec_mode = (pesieve::t_imprec_mode)myImp->value;
        }
    }
};
