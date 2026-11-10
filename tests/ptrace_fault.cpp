// Linked only into sdb-fault. Production sdb has no fault-injection path.
#include <sys/ptrace.h>
#include <sys/types.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
extern "C" long __real_ptrace(enum __ptrace_request request, ...);
extern "C" long __wrap_ptrace(enum __ptrace_request request, ...) {
    va_list arguments;
    va_start(arguments, request);
    pid_t pid = va_arg(arguments, pid_t);
    void* address = va_arg(arguments, void*);
    void* data = va_arg(arguments, void*);
    va_end(arguments);
    static bool configured = false;
    static unsigned selected = 0; // 0=poke, 1=xstate, 2=syscall-info
    static unsigned count = 0, first = 0, second = 0;
    if (request == PTRACE_POKEDATA || request == PTRACE_SETREGSET || request == PTRACE_GET_SYSCALL_INFO) {
        if (!configured) {
            const char* path = std::getenv("SDB_FAULT_FILE");
            if (path && access(path, F_OK) == 0) {
                FILE* file = std::fopen(path, "r");
                if (file) {
                    char mode[16]{};
                    if (std::fscanf(file, "%15s %u %u", mode, &first, &second) >= 2) {
                        selected = mode[0] == 'x' ? 1 : mode[0] == 's' ? 2 : 0;
                        configured = true;
                    }
                    std::fclose(file);
                }
            }
        }
        if (configured && ((selected == 1 && request == PTRACE_SETREGSET) ||
                           (selected == 0 && request == PTRACE_POKEDATA) ||
                           (selected == 2 && request == PTRACE_GET_SYSCALL_INFO))) {
            ++count;
            if (count == first || count == second) { errno = EIO; return -1; }
        }
    }
    return __real_ptrace(request, pid, address, data);
}
