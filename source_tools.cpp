#include "source_tools.h"
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <chrono>
#include <cerrno>
#include <sstream>
#include <regex>
#include <set>
#include <stdexcept>
extern char** environ;

std::string run_source_tool(const std::vector<std::string>& arguments) {
    if (arguments.empty()) throw std::runtime_error("missing source tool");
    int descriptors[2];
    if (pipe2(descriptors, O_CLOEXEC) < 0) throw std::runtime_error("cannot create source tool pipe");
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, descriptors[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, descriptors[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, descriptors[0]);
    posix_spawn_file_actions_addclose(&actions, descriptors[1]);
    std::vector<char*> argv;
    for (const auto& argument : arguments) argv.push_back(const_cast<char*>(argument.c_str()));
    argv.push_back(nullptr);
    pid_t child;
    int error = posix_spawnp(&child, argv[0], &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    close(descriptors[1]);
    if (error) { close(descriptors[0]); throw std::runtime_error("cannot launch " + arguments[0] + "; install binutils"); }
    std::string output;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
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
            if (output.size() > 16 * 1024 * 1024) throw std::runtime_error("source tool output exceeds 16 MiB limit");
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
    std::ostringstream value;
    value << "0x" << std::hex << address;
    auto output = run_source_tool({"addr2line", "-e", object, value.str()});
    auto end = output.find('\n');
    if (end != std::string::npos) output.resize(end);
    if (output.empty() || output.find("??") != std::string::npos)
        throw std::runtime_error("source location unavailable; rebuild with -g");
    auto annotation = output.find(" (discriminator ");
    if (annotation != std::string::npos) output.resize(annotation);
    return output;
}

std::vector<uint64_t> source_addresses(const std::string& object, const std::string& file, unsigned line) {
    auto output = run_source_tool({"readelf", "--debug-dump=decodedline", "--wide", object});
    std::istringstream input(output);
    std::string row;
    std::set<uint64_t> result;
    // Binutils decoded line rows: filename, decimal line, hex address, view, flags.
    std::regex pattern(R"(^\s*(.+?)\s+([0-9]+)\s+(0x[0-9a-fA-F]+)(?:\s.*)?$)");
    auto basename = [](const std::string& path) { return path.substr(path.find_last_of('/') + 1); };
    while (std::getline(input, row)) {
        std::smatch match;
        if (!std::regex_match(row, match, pattern)) continue;
        if (basename(match[1].str()) != basename(file) || std::stoul(match[2]) != line) continue;
        result.insert(std::stoull(match[3], nullptr, 16));
    }
    return {result.begin(), result.end()};
}
