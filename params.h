#pragma once

#include <paramkit.h>
using namespace paramkit;

#include "unpack_scanner.h"
#include "util/path_util.h"
#include "driver_comm.h"

#define DEFAULT_TIMEOUT 1000

#define PARAM_EXE "exe"
#define PARAM_IMG "img"
#define PARAM_CMD "cmd"
#define PARAM_TIMEOUT "timeout"
#define PARAM_OUT_DIR "dir"

#define PARAM_DATA "data"
#define PARAM_MINDUMP "minidmp"
#define PARAM_SHELLCODE "shellc"
#define PARAM_HOOKS "hooks"
#define PARAM_CACHE "cache"
#define PARAM_IMP "imp"
#define PARAM_NORESPAWN "noresp"
#define PARAM_TRIGGER "trigger"
#define PARAM_REFLECTION "refl"

typedef enum {
    TRIG_TIMEOUT = 0,
    TRIG_ANY = 1 ,
    COUNT_TRIG
} t_term_trigger;

typedef enum {
    NORESP_NO_RESTRICTION = 0,
    NORESP_DROPPED_FILES = 1,
    NORESP_ALL_FILES = 2,
    COUNT_NORESP
} t_noresp;

typedef struct {
    char exe_path[MAX_PATH];
    char exe_cmd[MAX_PATH];
    char out_dir[MAX_PATH];
    char img_path[MAX_PATH];
    DWORD timeout;
    t_term_trigger trigger;
    t_noresp noresp;
    UnpackScanner::t_unp_params hh_args;
} t_params_struct;


std::string version_to_str(DWORD version)
{
    BYTE* chunks = (BYTE*)&version;
    std::stringstream stream;
    stream << std::hex <<
        (int)chunks[3] << "." <<
        (int)chunks[2] << "." <<
        (int)chunks[1] << "." <<
        (int)chunks[0];

    return stream.str();
}

std::string translate_data_mode(const pesieve::t_data_scan_mode &mode)
{
    switch (mode) {
    case pesieve::PE_DATA_NO_SCAN:
        return "none: do not scan non-executable pages";
    case pesieve::PE_DATA_SCAN_DOTNET:
        return ".NET: scan non-executable in .NET applications";
    case pesieve::PE_DATA_SCAN_NO_DEP:
        return "if no DEP: scan non-exec if DEP is disabled (or if is .NET)";
    case pesieve::PE_DATA_SCAN_ALWAYS:
        return "always: scan non-executable pages unconditionally";
    case pesieve::PE_DATA_SCAN_INACCESSIBLE:
        return "include inaccessible: scan non-executable pages unconditionally;\n\t    in reflection mode (/refl): scan also inaccessible pages";
    case pesieve::PE_DATA_SCAN_INACCESSIBLE_ONLY:
        return "scan inaccessible pages, but exclude other non-executable;\n\t    works in reflection mode (/refl) only";
    }
    return "undefined";
}

std::string translate_imprec_mode(const pesieve::t_imprec_mode imprec_mode)
{
    switch (imprec_mode) {
    case pesieve::PE_IMPREC_NONE:
        return "none: do not recover imports";
    case pesieve::PE_IMPREC_AUTO:
        return "try to autodetect the most suitable mode";
    case pesieve::PE_IMPREC_UNERASE:
        return "unerase the erased parts of the partialy damaged ImportTable";
    case pesieve::PE_IMPREC_REBUILD0:
        return "build the ImportTable from scratch, basing on the found IATs:\n\t         use only terminated blocks (restrictive mode)";
    case pesieve::PE_IMPREC_REBUILD1:
        return "build the ImportTable from scratch, basing on the found IATs:\n\t         use terminated blocks, or blocks with more than 1 thunk";
    case pesieve::PE_IMPREC_REBUILD2:
        return "build the ImportTable from scratch, basing on the found IATs:\n\t         use all found blocks (aggressive mode)";
    }
    return "undefined";
}

bool addDataMode(EnumParam *dataParam, pesieve::t_data_scan_mode mode)
{
    if (!dataParam) {
        return false;
    }
    dataParam->addEnumValue(mode, translate_data_mode(mode));
    return true;
}

class UnpackParams : public Params
{
public:
    UnpackParams(const std::string &version)
        : Params(version)
    {
        this->addParam(new StringParam(PARAM_EXE, true));
        this->setInfo(PARAM_EXE, "Input exe (to be run)");

        this->addParam(new StringParam(PARAM_IMG, false));
        this->setInfo(PARAM_IMG, "Path to the image from which the malware was run (may be a DLL or EXE).\n\t   DEFAULT: same as /exe", 
            "\t   This allows to follow processes respawned from the given image.");

        this->addParam(new StringParam(PARAM_CMD, false));
        this->setInfo(PARAM_CMD, "Commandline arguments for the input exe");

        this->addParam(new IntParam(PARAM_TIMEOUT, true, IntParam::INT_BASE_DEC));
        this->setInfo(PARAM_TIMEOUT, "Timeout in miliseconds (0: infinity)");

        this->addParam(new StringParam(PARAM_OUT_DIR, false));
        this->setInfo(PARAM_OUT_DIR, "Set a root directory for the output (default: current directory)");

        //PARAM_REFLECTION
        this->addParam(new BoolParam(PARAM_REFLECTION, false));
        this->setInfo(PARAM_REFLECTION, "Make a process reflection before scan.", "\t   This allows i.e. to force-read inaccessible pages.");

        //PARAM_CACHE
        this->addParam(new BoolParam(PARAM_CACHE, false));
        this->setInfo(PARAM_CACHE, "Use modules caching.", "\t   This can speed up the scan (on the cost of memory consumption).");

        EnumParam *dataParam = new EnumParam(PARAM_DATA, "data_scan_mode", false);
        if (dataParam) {
            this->addParam(dataParam);
            this->setInfo(PARAM_DATA, "Set if non-executable pages should be scanned");
            addDataMode(dataParam, pesieve::t_data_scan_mode::PE_DATA_NO_SCAN);
            addDataMode(dataParam, pesieve::t_data_scan_mode::PE_DATA_SCAN_DOTNET);
            addDataMode(dataParam, pesieve::t_data_scan_mode::PE_DATA_SCAN_NO_DEP);
            addDataMode(dataParam, pesieve::t_data_scan_mode::PE_DATA_SCAN_ALWAYS);
            addDataMode(dataParam, pesieve::t_data_scan_mode::PE_DATA_SCAN_INACCESSIBLE);
            addDataMode(dataParam, pesieve::t_data_scan_mode::PE_DATA_SCAN_INACCESSIBLE_ONLY);
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
            impParam->addEnumValue(pesieve::t_imprec_mode::PE_IMPREC_NONE, "N", translate_imprec_mode(pesieve::t_imprec_mode::PE_IMPREC_NONE));
            impParam->addEnumValue(pesieve::t_imprec_mode::PE_IMPREC_AUTO, "A", translate_imprec_mode(pesieve::t_imprec_mode::PE_IMPREC_AUTO) + " [DEFAULT]");
            impParam->addEnumValue(pesieve::t_imprec_mode::PE_IMPREC_UNERASE, "U", translate_imprec_mode(pesieve::t_imprec_mode::PE_IMPREC_UNERASE));
            impParam->addEnumValue(pesieve::t_imprec_mode::PE_IMPREC_REBUILD0, "R0", translate_imprec_mode(pesieve::t_imprec_mode::PE_IMPREC_REBUILD0));
            impParam->addEnumValue(pesieve::t_imprec_mode::PE_IMPREC_REBUILD1, "R1", translate_imprec_mode(pesieve::t_imprec_mode::PE_IMPREC_REBUILD1));
            impParam->addEnumValue(pesieve::t_imprec_mode::PE_IMPREC_REBUILD2, "R2", translate_imprec_mode(pesieve::t_imprec_mode::PE_IMPREC_REBUILD2));
        }


        EnumParam* norespParam = new EnumParam(PARAM_NORESPAWN, "respawn_protect", false);
        if (norespParam) {

            std::stringstream ss;
            ss << "Protect against malware respawning after the unpacking session finished";

            this->addParam(norespParam);
            if (!driver::is_ready()) {
                norespParam->setActive(false);
                ss << "\n" << std::string(INFO_SPACER) + "(to activate, install MalUnpackCompanion driver)";
            }
            this->setInfo(PARAM_NORESPAWN, ss.str(),
                std::string(INFO_SPACER) + "WARNING: this will cause your sample to be restricted by the driver\n");
            norespParam->addEnumValue(t_noresp::NORESP_NO_RESTRICTION, "N", "disabled: allow the malware to be rerun freely [DEFAULT]");
            norespParam->addEnumValue(t_noresp::NORESP_DROPPED_FILES, "D", "dropped files: block dropped files");
            norespParam->addEnumValue(t_noresp::NORESP_ALL_FILES, "A", "all: block all associated files (including the main sample)");
        }

        //optional: group parameters
        std::string str_group = "1. scanner settings";
        this->addGroup(new ParamGroup(str_group));
        this->addParamToGroup(PARAM_REFLECTION, str_group);
        this->addParamToGroup(PARAM_CACHE, str_group);

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
        ss << "MalUnpack v." << this->versionStr;
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
        std::cout << "MalUnpackCompanion: " << getDriverInfo(false) << "\n\n";

        print_in_color(paramkit::WARNING_COLOR, "CAUTION: Supplied malware will be deployed! Use it on a VM only!\n");
    }

    void fillStruct(t_params_struct &ps)
    {
        copyCStr<StringParam>(PARAM_EXE, ps.exe_path, sizeof(ps.exe_path));
        copyCStr<StringParam>(PARAM_IMG, ps.img_path, sizeof(ps.img_path));
        copyCStr<StringParam>(PARAM_CMD, ps.exe_cmd, sizeof(ps.exe_cmd));
        copyCStr<StringParam>(PARAM_OUT_DIR, ps.out_dir, sizeof(ps.out_dir));

        copyVal<IntParam>(PARAM_TIMEOUT, ps.timeout);
        copyVal<EnumParam>(PARAM_TRIGGER, ps.trigger);
        copyVal<EnumParam>(PARAM_NORESPAWN, ps.noresp);
        fillPEsieveStruct(ps.hh_args.pesieve_args);
    }

    virtual void printVersionInfo()
    {
        if (versionStr.length()) {
            std::cout << "MalUnpack: v." << versionStr << std::endl;
            std::cout << "MalUnpackCompanion: "<<  getDriverInfo(true) << std::endl;
        }
    }

protected:
    std::string getDriverInfo(bool showNodes)
    {
        ULONGLONG nodesCount = 0;
        ULONGLONG *nodesCountPtr = &nodesCount;
        char buf[100] = { 0 };
        if (!showNodes) {
            nodesCountPtr = nullptr;
        }

        driver::DriverStatus status = driver::get_version(buf, _countof(buf), nodesCountPtr);

        switch (status) {
        case driver::DriverStatus::DRIVER_UNAVAILABLE:
            return "driver not loaded";
        case driver::DriverStatus::DRIVER_NOT_RESPONDING:
            return "ERROR - driver not responding";
        case driver::DriverStatus::DRIVER_OK:
            if (buf) {
                std::stringstream ss;
                ss << "v." << std::string(buf);
                if (showNodes) {
                    ss << " (active sessions: " << std::dec << nodesCount << ")";
                }
                return ss.str();
            }
        default:
            return "could not fetch the version";
        }
    }

    void fillPEsieveStruct(pesieve::t_params &ps)
    {
        bool hooks = false;
        copyVal<BoolParam>(PARAM_HOOKS, hooks);
        ps.no_hooks = hooks ? false : true;

        copyVal<BoolParam>(PARAM_REFLECTION, ps.make_reflection);
        copyVal<BoolParam>(PARAM_MINDUMP, ps.minidump);
        copyVal<BoolParam>(PARAM_SHELLCODE, ps.shellcode);
        copyVal<EnumParam>(PARAM_IMP, ps.imprec_mode);
        copyVal<EnumParam>(PARAM_DATA, ps.data);
        copyVal<BoolParam>(PARAM_CACHE, ps.use_cache);
    }

};
