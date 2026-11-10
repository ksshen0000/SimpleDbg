#ifndef SIMPLEDBG_PROCESS_MAPS_H
#define SIMPLEDBG_PROCESS_MAPS_H
#include <sys/types.h>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include "symbols.h"

struct ProcessMapping {
    uint64_t start, end, offset;
    std::string permissions, path, device, inode;
    bool operator==(const ProcessMapping& other) const {
        return start == other.start && end == other.end && offset == other.offset &&
               permissions == other.permissions && path == other.path && device == other.device && inode == other.inode;
    }
};
struct LoadedObject {
    std::string path;
    uint64_t bias;
    std::shared_ptr<const ElfSymbols> symbols;
    std::string error;
};
std::vector<ProcessMapping> process_maps(pid_t pid);
std::vector<LoadedObject> loaded_objects(pid_t pid);
#endif
