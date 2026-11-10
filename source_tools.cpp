#include "source_tools.h"
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
extern char** environ;

namespace {
constexpr auto one_shot_timeout = std::chrono::seconds(15);
constexpr auto query_timeout = std::chrono::seconds(5);
constexpr size_t tool_output_limit = 16 * 1024 * 1024;
constexpr size_t debug_line_scan_limit = 64 * 1024 * 1024;

struct SpawnContext {
    posix_spawn_file_actions_t actions{};
    posix_spawnattr_t attributes{};
    SpawnContext() {
        posix_spawn_file_actions_init(&actions);
        posix_spawnattr_init(&attributes);
    }
    ~SpawnContext() {
        posix_spawn_file_actions_destroy(&actions);
        posix_spawnattr_destroy(&attributes);
    }
    SpawnContext(const SpawnContext&) = delete;
    SpawnContext& operator=(const SpawnContext&) = delete;
};

// The debugger keeps its own SIGINT handler while the target runs; helper
// tools must not inherit it or kill the interrupted target themselves.
void reset_child_signals(posix_spawnattr_t& attributes) {
    sigset_t defaults;
    sigemptyset(&defaults);
    sigaddset(&defaults, SIGINT);
    sigaddset(&defaults, SIGQUIT);
    sigaddset(&defaults, SIGPIPE);
    posix_spawnattr_setsigdefault(&attributes, &defaults);
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSIGDEF);
}

bool same_file(const struct stat& a, const struct stat& b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size &&
           a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
           a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}

std::string basename(const std::string& path) {
    auto slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string trim(const std::string& value) {
    auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

// Long-lived `addr2line -e OBJECT` process. It reads one address per line and
// prints one result per line, so a `step` over a source line no longer spawns
// one tool process per executed instruction.
class Addr2Line {
public:
    explicit Addr2Line(std::string object) : object_(std::move(object)) {}
    ~Addr2Line() { stop(); }
    Addr2Line(const Addr2Line&) = delete;
    Addr2Line& operator=(const Addr2Line&) = delete;

    std::string locate(uint64_t address) {
        for (unsigned attempt = 0; attempt < 2; ++attempt) {
            try {
                ensure_started();
                request(address);
                return response();
            } catch (...) {
                stop();
                if (attempt) throw;
            }
        }
        throw std::runtime_error("addr2line is unavailable");
    }

private:
    static struct stat identity_of(const std::string& path) {
        struct stat info{};
        if (stat(path.c_str(), &info) < 0) throw std::runtime_error("source object is unavailable");
        return info;
    }
    void ensure_started() {
        auto current = identity_of(object_);
        if (pid_ > 0 && same_file(identity_, current)) return;
        stop();
        start();
    }
    void start() {
        int input[2], output[2];
        if (pipe2(input, O_CLOEXEC) < 0) throw std::runtime_error("cannot create addr2line pipe");
        if (pipe2(output, O_CLOEXEC) < 0) {
            close(input[0]);
            close(input[1]);
            throw std::runtime_error("cannot create addr2line pipe");
        }
        SpawnContext spawn;
        posix_spawn_file_actions_adddup2(&spawn.actions, input[0], STDIN_FILENO);
        posix_spawn_file_actions_adddup2(&spawn.actions, output[1], STDOUT_FILENO);
        posix_spawn_file_actions_addopen(&spawn.actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
        posix_spawn_file_actions_addclose(&spawn.actions, input[0]);
        posix_spawn_file_actions_addclose(&spawn.actions, input[1]);
        posix_spawn_file_actions_addclose(&spawn.actions, output[0]);
        posix_spawn_file_actions_addclose(&spawn.actions, output[1]);
        reset_child_signals(spawn.attributes);
        char* arguments[] = {const_cast<char*>("addr2line"), const_cast<char*>("-e"),
                             const_cast<char*>(object_.c_str()), nullptr};
        pid_t child = -1;
        int error = posix_spawnp(&child, arguments[0], &spawn.actions, &spawn.attributes, arguments, environ);
        close(input[0]);
        close(output[1]);
        if (error) {
            close(input[1]);
            close(output[0]);
            throw std::runtime_error("cannot launch addr2line; install binutils");
        }
        pid_ = child;
        input_ = input[1];
        output_ = output[0];
        identity_ = identity_of(object_);
        buffered_.clear();
    }
    void stop() noexcept {
        if (input_ >= 0) close(input_);
        if (output_ >= 0) close(output_);
        if (pid_ > 0) {
            kill(pid_, SIGKILL);
            while (waitpid(pid_, nullptr, 0) < 0 && errno == EINTR) {}
        }
        input_ = output_ = -1;
        pid_ = -1;
        buffered_.clear();
    }
    void request(uint64_t address) {
        std::ostringstream text;
        text << "0x" << std::hex << address << '\n';
        const std::string payload = text.str();
        size_t written = 0;
        while (written < payload.size()) {
            ssize_t count = write(input_, payload.data() + written, payload.size() - written);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) throw std::runtime_error("cannot query addr2line");
            written += static_cast<size_t>(count);
        }
    }
    std::string response() {
        const auto deadline = std::chrono::steady_clock::now() + query_timeout;
        for (;;) {
            auto newline = buffered_.find('\n');
            if (newline != std::string::npos) {
                std::string line = buffered_.substr(0, newline);
                buffered_.erase(0, newline + 1);
                return line;
            }
            auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0) throw std::runtime_error("addr2line timed out");
            pollfd descriptor{output_, POLLIN, 0};
            int ready = poll(&descriptor, 1, static_cast<int>(std::min<long long>(left, 1000)));
            if (ready < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error("addr2line pipe failed");
            }
            if (!ready) continue;
            char bytes[4096];
            ssize_t count = read(output_, bytes, sizeof(bytes));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) throw std::runtime_error("addr2line terminated");
            buffered_.append(bytes, static_cast<size_t>(count));
            if (buffered_.size() > (1u << 20)) throw std::runtime_error("addr2line output is too large");
        }
    }

    std::string object_;
    struct stat identity_{};
    pid_t pid_ = -1;
    int input_ = -1;
    int output_ = -1;
    std::string buffered_;
};

Addr2Line& addr2line_for(const std::string& object) {
    static std::map<std::string, std::unique_ptr<Addr2Line>> cache;
    auto found = cache.find(object);
    if (found != cache.end()) return *found->second;
    if (cache.size() >= 4) cache.erase(cache.begin());
    return *cache.emplace(object, std::make_unique<Addr2Line>(object)).first->second;
}

struct LineRow {
    uint64_t address;
    unsigned line;
    std::string file;
};

// Decoded line rows from `readelf --debug-dump=decodedline`, parsed once per
// object instead of once per `break file:line`. Rows look like:
//     target.c   5   0x1139   x
//     target.c   -   0x11cc
class LineTable {
public:
    void parse(const std::string& output) {
        std::istringstream input(output);
        std::string line;
        while (std::getline(input, line)) {
            if (line.empty()) continue;
            std::vector<std::string> tokens;
            std::vector<size_t> starts;
            for (size_t cursor = 0; cursor < line.size();) {
                while (cursor < line.size() && std::isspace(static_cast<unsigned char>(line[cursor]))) ++cursor;
                size_t begin = cursor;
                while (cursor < line.size() && !std::isspace(static_cast<unsigned char>(line[cursor]))) ++cursor;
                if (begin < cursor) {
                    tokens.emplace_back(line, begin, cursor - begin);
                    starts.push_back(begin);
                }
            }
            if (tokens.size() < 3) continue;
            size_t address_token = SIZE_MAX;
            for (size_t i = 0; i < tokens.size(); ++i) {
                const auto& token = tokens[i];
                if (token.size() > 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
                    address_token = i;
                    break;
                }
            }
            if (address_token == SIZE_MAX || address_token == 0) continue;
            const auto& number = tokens[address_token - 1];
            if (number.find_first_not_of("0123456789") != std::string::npos) continue;
            std::string file = basename(trim(line.substr(0, starts[address_token - 1])));
            if (file.empty()) continue;
            try {
                rows_.push_back({std::stoull(tokens[address_token], nullptr, 16),
                                 static_cast<unsigned>(std::stoul(number)), std::move(file)});
            } catch (const std::exception&) {
                continue;
            }
        }
        std::sort(rows_.begin(), rows_.end(), [](const LineRow& a, const LineRow& b) {
            return a.address < b.address;
        });
    }
    const std::vector<LineRow>& rows() const { return rows_; }

private:
    std::vector<LineRow> rows_;
};

bool contains_debug_line(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return false;
    auto size = file.tellg();
    if (size < 0) return false;
    if (static_cast<uint64_t>(size) > debug_line_scan_limit) return true; // let readelf decide
    file.seekg(0);
    std::string bytes(static_cast<size_t>(size), '\0');
    if (size && !file.read(bytes.data(), static_cast<std::streamsize>(size))) return false;
    return bytes.find(".debug_line") != std::string::npos;
}

// Cheap negative check so `bt`/`where` do not spawn addr2line for objects
// without DWARF (for example libc). Result is cached per file identity.
bool debug_line_available(const std::string& object) {
    struct Cached {
        struct stat identity{};
        bool present = false;
    };
    static std::map<std::string, Cached> cache;
    struct stat identity{};
    if (stat(object.c_str(), &identity) < 0) return false;
    auto found = cache.find(object);
    if (found != cache.end() && same_file(found->second.identity, identity)) return found->second.present;
    bool present = contains_debug_line(object);
    if (cache.size() >= 16) cache.erase(cache.begin());
    cache[object] = {identity, present};
    return present;
}

std::shared_ptr<const LineTable> line_table_for(const std::string& object) {
    struct Cached {
        struct stat identity{};
        std::shared_ptr<const LineTable> table;
    };
    static std::map<std::string, Cached> cache;
    struct stat identity{};
    if (stat(object.c_str(), &identity) < 0) throw std::runtime_error("source object is unavailable");
    auto found = cache.find(object);
    if (found != cache.end() && same_file(found->second.identity, identity)) return found->second.table;
    auto table = std::make_shared<LineTable>();
    if (debug_line_available(object))
        table->parse(run_source_tool({"readelf", "--debug-dump=decodedline", "--wide", object}));
    if (cache.size() >= 8) cache.erase(cache.begin());
    cache[object] = {identity, table};
    return table;
}
} // namespace

std::string run_source_tool(const std::vector<std::string>& arguments) {
    if (arguments.empty()) throw std::runtime_error("missing source tool");
    int descriptors[2];
    if (pipe2(descriptors, O_CLOEXEC) < 0) throw std::runtime_error("cannot create source tool pipe");
    SpawnContext spawn;
    posix_spawn_file_actions_adddup2(&spawn.actions, descriptors[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&spawn.actions, descriptors[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&spawn.actions, descriptors[0]);
    posix_spawn_file_actions_addclose(&spawn.actions, descriptors[1]);
    reset_child_signals(spawn.attributes);
    std::vector<char*> argv;
    for (const auto& argument : arguments) argv.push_back(const_cast<char*>(argument.c_str()));
    argv.push_back(nullptr);
    pid_t child;
    int error = posix_spawnp(&child, argv[0], &spawn.actions, &spawn.attributes, argv.data(), environ);
    close(descriptors[1]);
    if (error) {
        close(descriptors[0]);
        throw std::runtime_error("cannot launch " + arguments[0] + "; install binutils");
    }
    std::string output;
    auto deadline = std::chrono::steady_clock::now() + one_shot_timeout;
    int status = 0;
    try {
        for (;;) {
            if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error("source tool timed out");
            pollfd fd{descriptors[0], POLLIN, 0};
            int ready = poll(&fd, 1, 100);
            if (ready < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error("source tool pipe failed");
            }
            if (!ready) continue;
            char bytes[4096];
            ssize_t count = read(descriptors[0], bytes, sizeof(bytes));
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) throw std::runtime_error("cannot read source tool output");
            if (!count) break;
            output.append(bytes, count);
            if (output.size() > tool_output_limit) throw std::runtime_error("source tool output exceeds 16 MiB limit");
        }
        while (waitpid(child, &status, 0) < 0) {
            if (errno != EINTR) throw std::runtime_error("cannot wait for source tool");
        }
    } catch (...) {
        kill(child, SIGKILL);
        while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {}
        close(descriptors[0]);
        throw;
    }
    close(descriptors[0]);
    if (!WIFEXITED(status) || WEXITSTATUS(status)) throw std::runtime_error("source tool failed: " + output.substr(0, 200));
    return output;
}

std::string source_location(const std::string& object, uint64_t address) {
    if (!debug_line_available(object))
        throw std::runtime_error("source location unavailable; rebuild with -g");
    std::string output;
    try {
        output = addr2line_for(object).locate(address);
    } catch (const std::exception&) {
        std::ostringstream value;
        value << "0x" << std::hex << address;
        output = run_source_tool({"addr2line", "-e", object, value.str()});
        auto end = output.find('\n');
        if (end != std::string::npos) output.resize(end);
    }
    auto annotation = output.find(" (discriminator ");
    if (annotation != std::string::npos) output.resize(annotation);
    while (!output.empty() && (output.back() == '\r' || output.back() == ' ')) output.pop_back();
    // addr2line reports missing DWARF as "??:0", "??:?" or ":?"; require a
    // non-empty file name and a positive decimal line.
    auto colon = output.find_last_of(':');
    if (colon == std::string::npos || colon == 0) throw std::runtime_error("source location unavailable; rebuild with -g");
    const std::string file = output.substr(0, colon);
    const std::string line = output.substr(colon + 1);
    if (file == "??" || file.find_first_not_of('?') == std::string::npos ||
        line.empty() || line.find_first_not_of("0123456789") != std::string::npos)
        throw std::runtime_error("source location unavailable; rebuild with -g");
    try {
        if (std::stoul(line) == 0) throw std::runtime_error("source location unavailable; rebuild with -g");
    } catch (const std::out_of_range&) {
        throw std::runtime_error("source location unavailable; rebuild with -g");
    }
    return output;
}

std::vector<uint64_t> source_addresses(const std::string& object, const std::string& file, unsigned line) {
    auto table = line_table_for(object);
    std::set<uint64_t> result;
    const std::string wanted = basename(file);
    for (const auto& row : table->rows()) {
        if (row.line == line && row.file == wanted) result.insert(row.address);
    }
    return {result.begin(), result.end()};
}
