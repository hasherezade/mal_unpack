#include "path_util.h"

std::string make_dir_name(std::string baseDir, time_t timestamp, const std::string &prefix)
{
    std::stringstream stream;
    if (baseDir.length() > 0) {
        stream << baseDir;
        stream << "\\";
    }
    stream << prefix;
    stream << timestamp;
    return stream.str();
}

const char* get_file_name(const char *full_path)
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
