#include "process_maps.h"
#include <elf.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <set>
#include <sys/stat.h>

namespace {
std::shared_ptr<const ElfSymbols> cached_symbols(const ProcessMapping& mapping) {
    struct stat identity{};
    if (stat(mapping.path.c_str(), &identity) < 0) throw std::runtime_error("ELF file is unavailable");
    // Device numbers in /proc/<pid>/maps can differ from stat(2) inside
    // containers, btrfs subvolumes and mount namespaces even though the path
    // still names the mapped file. The inode is stable across those views, so
    // compare it (plus the cached size/timestamps) instead of the device.
    uint64_t inode = 0;
    try { inode = std::stoull(mapping.inode); }
    catch (const std::exception&) { throw std::runtime_error("invalid inode in process mapping"); }
    if (inode != identity.st_ino)
        throw std::runtime_error("ELF path no longer refers to the mapped file");
    struct Cached { struct stat identity; std::shared_ptr<const ElfSymbols> symbols; };
    static std::map<std::string, Cached> cache;
    auto found = cache.find(mapping.path);
    if (found != cache.end()) {
        const auto& previous = found->second.identity;
        if (previous.st_dev == identity.st_dev && previous.st_ino == identity.st_ino &&
            previous.st_size == identity.st_size && previous.st_mtim.tv_sec == identity.st_mtim.tv_sec &&
            previous.st_mtim.tv_nsec == identity.st_mtim.tv_nsec && previous.st_ctim.tv_sec == identity.st_ctim.tv_sec &&
            previous.st_ctim.tv_nsec == identity.st_ctim.tv_nsec) return found->second.symbols;
    }
    auto symbols = std::make_shared<ElfSymbols>();
    symbols->load(mapping.path);
    if (cache.size() >= 64) cache.erase(cache.begin());
    cache[mapping.path] = {identity, symbols};
    return symbols;
}
}

namespace {
// The target is stopped while commands run, so its mappings and loaded objects
// cannot change between two queries. Cache them until the tracee is resumed.
struct ProcessView {
    pid_t pid = -1;
    bool maps_valid = false;
    bool objects_valid = false;
    std::vector<ProcessMapping> maps;
    std::vector<LoadedObject> objects;
} view;

void load_maps(pid_t pid) {
    if (view.maps_valid && view.pid == pid) return;
    view = ProcessView{};
    view.pid = pid;
    std::ifstream file("/proc/" + std::to_string(pid) + "/maps");
    if (!file) throw std::runtime_error("process mappings are unavailable");
    std::vector<ProcessMapping> result;
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream input(line);
        std::string range;
        ProcessMapping map{};
        if (!(input >> range >> map.permissions >> std::hex >> map.offset >> map.device >> map.inode))
            throw std::runtime_error("invalid process mapping");
        auto dash = range.find('-');
        if (dash == std::string::npos) throw std::runtime_error("invalid mapping range");
        try {
            map.start = std::stoull(range.substr(0, dash), nullptr, 16);
            map.end = std::stoull(range.substr(dash + 1), nullptr, 16);
        } catch (const std::exception&) {
            throw std::runtime_error("invalid mapping range");
        }
        std::getline(input >> std::ws, map.path);
        result.push_back(std::move(map));
    }
    view.maps = std::move(result);
    view.maps_valid = true;
}
}

void invalidate_process_view() { view = ProcessView{}; }

std::vector<ProcessMapping> process_maps(pid_t pid) {
    load_maps(pid);
    return view.maps;
}

std::vector<LoadedObject> loaded_objects(pid_t pid) {
    load_maps(pid);
    if (view.objects_valid) return view.objects;
    std::vector<LoadedObject> result;
    std::set<std::pair<std::string, uint64_t>> seen;
    const uint64_t page = static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
    const auto& mappings = view.maps;
    for (const auto& map : mappings) {
        if (map.offset || map.path.empty() || map.path[0] != '/') continue;
        std::ifstream file(map.path, std::ios::binary);
        Elf64_Ehdr header{};
        if (!file.read(reinterpret_cast<char*>(&header), sizeof(header)) ||
            header.e_ident[0] != ELFMAG0 || header.e_ident[1] != ELFMAG1 ||
            header.e_ident[2] != ELFMAG2 || header.e_ident[3] != ELFMAG3 ||
            header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_machine != EM_X86_64 ||
            header.e_phentsize != sizeof(Elf64_Phdr)) continue;
        if (header.e_phoff > UINT64_MAX - uint64_t(header.e_phnum) * sizeof(Elf64_Phdr)) continue;
        std::vector<Elf64_Phdr> segments(header.e_phnum);
        file.seekg(header.e_phoff);
        if (segments.size() &&
            !file.read(reinterpret_cast<char*>(segments.data()), segments.size() * sizeof(Elf64_Phdr))) continue;
        for (const auto& segment : segments) {
            if (segment.p_type != PT_LOAD || segment.p_offset != 0) continue;
            uint64_t base = segment.p_vaddr - segment.p_vaddr % page;
            if (map.start < base) break;
            uint64_t bias = map.start - base;
            // A RELRO/data segment can also map file offset zero. Verify that
            // this bias places executable LOAD segments in executable mappings.
            bool valid = true;
            for (const auto& code : segments) {
                if (code.p_type != PT_LOAD || !(code.p_flags & PF_X) || !code.p_memsz) continue;
                if (code.p_vaddr > UINT64_MAX - bias) { valid = false; break; }
                uint64_t address = bias + code.p_vaddr;
                bool mapped = false;
                for (const auto& candidate : mappings) {
                    if (candidate.path == map.path && candidate.start <= address && address < candidate.end &&
                        candidate.permissions.size() == 4 && candidate.permissions[2] == 'x' &&
                        address - candidate.start + candidate.offset == code.p_offset) {
                        mapped = true;
                        break;
                    }
                }
                if (!mapped) { valid = false; break; }
            }
            if (!valid || !seen.emplace(map.path, bias).second) break;
            LoadedObject object{map.path, bias, {}, {}};
            try { object.symbols = cached_symbols(map); }
            catch (const std::exception& error) {
                object.error = error.what();
                object.symbols = std::make_shared<ElfSymbols>();
            }
            result.push_back(std::move(object));
            break;
        }
    }
    view.objects = std::move(result);
    view.objects_valid = true;
    return view.objects;
}
