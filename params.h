#pragma once

#include <paramkit.h>
using namespace paramkit;

#include "unpack_scanner.h"
#include "util.h"

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
#define PARAM_REFLECTION "refl"

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
    UnpackParams(const std::string &version)
        : Params(version)
    {
        this->addParam(new StringParam(PARAM_EXE, true));
        this->setInfo(PARAM_EXE, "Input exe (to be run)");

        this->addParam(new StringParam(PARAM_CMD, false));
        this->setInfo(PARAM_CMD, "Commandline arguments for the input exe");

        this->addParam(new IntParam(PARAM_TIMEOUT, true, IntParam::INT_BASE_DEC));
        this->setInfo(PARAM_TIMEOUT, "Timeout in miliseconds (0: infinity)");

        this->addParam(new StringParam(PARAM_OUT_DIR, false));
        this->setInfo(PARAM_OUT_DIR, "Set a root directory for the output (default: current directory)");

        //PARAM_REFLECTION
        this->addParam(new BoolParam(PARAM_REFLECTION, false));
        this->setInfo(PARAM_REFLECTION, "Make a process reflection before scan.", "\t   This allows i.e. to force-read inaccessible pages.");

        EnumParam *dataParam = new EnumParam(PARAM_DATA, "data_scan_mode", false);
        if (dataParam) {
            this->addParam(dataParam);
            this->setInfo(PARAM_DATA, "Set if non-executable pages should be scanned");
            dataParam->addEnumValue(pesieve::t_data_scan_mode::PE_DATA_NO_SCAN, "none: do not scan non-executable pages");
            dataParam->addEnumValue(pesieve::t_data_scan_mode::PE_DATA_SCAN_DOTNET, ".NET: scan non-executable in .NET applications [DEFAULT]");
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
        std::string str_group = "1. scanner settings";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_REFLECTION, str_group);

        str_group = "2. scan options";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_DATA, str_group);
        this->addParamToGroup(PARAM_SHELLCODE, str_group);
        this->addParamToGroup(PARAM_HOOKS, str_group);

        str_group = "3. dump options";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_MINDUMP, str_group);
        this->addParamToGroup(PARAM_IMP, str_group);

        str_group = "4. output options";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_OUT_DIR, str_group);
    }

    void printBanner()
    {
        std::stringstream ss;
        ss << "mal_unpack " << this->versionStr;
#ifdef _WIN64
        ss << " (x64)" << "\n";
#else
        ss << " (x86)" << "\n";
#endif
        ss << "Dynamic malware unpacker\n";
        ss << "Built on: " << __DATE__;

        paramkit::print_in_color(MAKE_COLOR(WHITE, BLACK), ss.str());
        std::cout << "\n";
        DWORD pesieve_ver = PESieve_version;
        std::cout << "using: PE-sieve v." << version_to_str(pesieve_ver) << "\n\n";

        print_in_color(paramkit::WARNING_COLOR, "CAUTION: Supplied malware will be deployed! Use it on a VM only!\n");
    }

    void fillStruct(t_params_struct &ps)
    {
        copyCStr<StringParam>(PARAM_EXE, ps.exe_path, sizeof(ps.exe_path));
        copyCStr<StringParam>(PARAM_CMD, ps.exe_cmd, sizeof(ps.exe_cmd));
        copyCStr<StringParam>(PARAM_OUT_DIR, ps.out_dir, sizeof(ps.out_dir));

        copyVal<IntParam>(PARAM_TIMEOUT, ps.timeout);
        copyVal<EnumParam>(PARAM_TRIGGER, ps.trigger);

        fillPEsieveStruct(ps.hh_args.pesieve_args);
    }

protected:
    void fillPEsieveStruct(pesieve::t_params &ps)
    {
        bool hooks = false;
        copyVal<BoolParam>(PARAM_HOOKS, hooks);
        ps.no_hooks = hooks ? false : true;

        copyVal<BoolParam>(PARAM_REFLECTION, ps.make_reflection);
        copyVal<BoolParam>(PARAM_MINDUMP, ps.minidump);
        copyVal<BoolParam>(PARAM_SHELLCODE, ps.shellcode);
        copyVal<BoolParam>(PARAM_IMP, ps.imprec_mode);
        copyVal<EnumParam>(PARAM_DATA, ps.data);
    }

};
