#include "util.h"

std::string version_to_str(DWORD version)
{
    BYTE *chunks = (BYTE*)&version;
    std::stringstream stream;
    stream << std::hex <<
        (int)chunks[3] << "." <<
        (int)chunks[2] << "." <<
        (int)chunks[1] << "." <<
        (int)chunks[0];

    return stream.str();
}

std::string make_dir_name(std::string baseDir, time_t timestamp)
{
    std::stringstream stream;
    if (baseDir.length() > 0) {
        stream << baseDir;
        stream << "\\";
    }
    stream << "scan_";
    stream << timestamp;
    return stream.str();
}

bool set_output_dir(pesieve::t_params &args, const char *new_dir)
{
    if (!new_dir) return false;

    size_t new_len = strlen(new_dir);
    size_t buffer_len = sizeof(args.output_dir);
    if (new_len > buffer_len) return false;

    memset(args.output_dir, 0, buffer_len);
    memcpy(args.output_dir, new_dir, new_len);
    return true;
}

char* get_file_name(char *full_path)
{
    if (!full_path) return nullptr;

    size_t len = strlen(full_path);
    if (len < 2) {
        return full_path;
    }
    for (size_t i = len - 2; i > 0; i--) {
        if (full_path[i] == '\\' || full_path[i] == '/') {
            return full_path + (i + 1);
        }
    }
    return full_path;
}
