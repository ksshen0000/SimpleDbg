// Linked only into sdb-fault. Production sdb has no fault-injection path.
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>

extern "C" long __real_ptrace(enum __ptrace_request request, ...);
extern "C" ssize_t __real_process_vm_writev(pid_t pid, const struct iovec* local, unsigned long local_count,
                                            const struct iovec* remote, unsigned long remote_count,
                                            unsigned long flags);

namespace {
enum Target : unsigned { kPoke = 0, kXState = 1, kSyscallInfo = 2, kVmWrite = 3 };
struct Config {
    bool configured = false;
    unsigned selected = kPoke;
    unsigned count = 0, first = 0, second = 0;
    int error = EIO;
};
Config& config() {
    static Config state;
    return state;
}
// The control file appears after the session starts, so retry until it exists.
bool trigger(unsigned target) {
    auto& state = config();
    if (!state.configured) {
        const char* path = std::getenv("SDB_FAULT_FILE");
        if (!path || access(path, F_OK) != 0) return false;
        FILE* file = std::fopen(path, "r");
        if (!file) return false;
        char mode[16]{};
        if (std::fscanf(file, "%15s %u %u", mode, &state.first, &state.second) >= 2) {
            if (mode[0] == 'x') state.selected = kXState;
            else if (mode[0] == 's') state.selected = kSyscallInfo;
            else if (mode[0] == 'v' || mode[0] == 'e') {
                state.selected = kVmWrite;
                // "e" simulates a kernel without process_vm_writev so the
                // debugger exercises its ptrace fallback.
                state.error = mode[0] == 'e' ? ENOSYS : EIO;
            } else state.selected = kPoke;
            state.configured = true;
        }
        std::fclose(file);
        if (!state.configured) return false;
    }
    if (state.selected != target) return false;
    ++state.count;
    return state.count == state.first || state.count == state.second;
}
} // namespace

extern "C" long __wrap_ptrace(enum __ptrace_request request, ...) {
    va_list arguments;
    va_start(arguments, request);
    pid_t pid = va_arg(arguments, pid_t);
    void* address = va_arg(arguments, void*);
    void* data = va_arg(arguments, void*);
    va_end(arguments);
    unsigned target = 0xffffu;
    if (request == PTRACE_POKEDATA) target = kPoke;
    else if (request == PTRACE_SETREGSET) target = kXState;
    else if (request == PTRACE_GET_SYSCALL_INFO) target = kSyscallInfo;
    if (target != 0xffffu && trigger(target)) { errno = config().error; return -1; }
    return __real_ptrace(request, pid, address, data);
}

extern "C" ssize_t __wrap_process_vm_writev(pid_t pid, const struct iovec* local, unsigned long local_count,
                                            const struct iovec* remote, unsigned long remote_count,
                                            unsigned long flags) {
    if (trigger(kVmWrite)) { errno = config().error; return -1; }
    return __real_process_vm_writev(pid, local, local_count, remote, remote_count, flags);
}
