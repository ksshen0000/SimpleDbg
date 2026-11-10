#include "sdb.h"
#include "process_maps.h"
#include "source_tools.h"
#include <fcntl.h>
#include <sys/uio.h>
#include <cpuid.h>

#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>

static_assert(sizeof(long) == 8, "SimpleDbg requires Linux x86-64");

namespace {
volatile sig_atomic_t interrupt_pid = 0;
volatile sig_atomic_t target_running = 0;
volatile sig_atomic_t pause_requested = 0;
volatile sig_atomic_t quit_requested = 0;
void on_interrupt(int) {
    int saved = errno;
    if (target_running && !pause_requested) {
        pause_requested = 1;
        if (interrupt_pid > 0) kill(interrupt_pid, SIGSTOP);
    } else {
        quit_requested = 1;
        if (interrupt_pid > 0) kill(interrupt_pid, SIGKILL);
    }
    errno = saved;
}
struct ExecutionScope {
    sig_atomic_t previous = target_running;
    ExecutionScope() {
        // The tracee may mmap/munmap/mprotect/dlopen while running; drop the
        // stopped-process view before every resume.
        invalidate_process_view();
        target_running = 1;
    }
    ~ExecutionScope() { target_running = previous; }
};
std::runtime_error system_error(const std::string& action) {
    return std::runtime_error(action + ": " + std::strerror(errno));
}
uint64_t parse_number(const std::string& value, int base) {
    if (value.empty() || value[0] == '-' || value[0] == '+')
        throw std::runtime_error("invalid number: " + value);
    size_t consumed = 0;
    uint64_t number = std::stoull(value, &consumed, base);
    if (consumed != value.size()) throw std::runtime_error("invalid number: " + value);
    return number;
}
const char* signal_name(int number) {
    switch (number) {
        case SIGHUP: return "SIGHUP";
        case SIGINT: return "SIGINT";
        case SIGQUIT: return "SIGQUIT";
        case SIGILL: return "SIGILL";
        case SIGTRAP: return "SIGTRAP";
        case SIGABRT: return "SIGABRT";
        case SIGBUS: return "SIGBUS";
        case SIGFPE: return "SIGFPE";
        case SIGKILL: return "SIGKILL";
        case SIGUSR1: return "SIGUSR1";
        case SIGSEGV: return "SIGSEGV";
        case SIGUSR2: return "SIGUSR2";
        case SIGPIPE: return "SIGPIPE";
        case SIGALRM: return "SIGALRM";
        case SIGCHLD: return "SIGCHLD";
        case SIGCONT: return "SIGCONT";
        case SIGSTOP: return "SIGSTOP";
        case SIGTSTP: return "SIGTSTP";
        case SIGTTIN: return "SIGTTIN";
        case SIGTTOU: return "SIGTTOU";
        case SIGSYS: return "SIGSYS";
        default: return nullptr;
    }
}
const char* syscall_name(Address number) {
    switch (number) {
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
        case 3: return "close";
        case 4: return "stat";
        case 5: return "fstat";
        case 6: return "lstat";
        case 7: return "poll";
        case 8: return "lseek";
        case 9: return "mmap";
        case 10: return "mprotect";
        case 11: return "munmap";
        case 12: return "brk";
        case 13: return "rt_sigaction";
        case 14: return "rt_sigprocmask";
        case 15: return "rt_sigreturn";
        case 16: return "ioctl";
        case 17: return "pread64";
        case 18: return "pwrite64";
        case 19: return "readv";
        case 20: return "writev";
        case 21: return "access";
        case 22: return "pipe";
        case 23: return "select";
        case 24: return "sched_yield";
        case 25: return "mremap";
        case 32: return "dup";
        case 33: return "dup2";
        case 35: return "nanosleep";
        case 39: return "getpid";
        case 41: return "socket";
        case 42: return "connect";
        case 43: return "accept";
        case 44: return "sendto";
        case 45: return "recvfrom";
        case 49: return "bind";
        case 50: return "listen";
        case 53: return "socketpair";
        case 56: return "clone";
        case 57: return "fork";
        case 58: return "vfork";
        case 59: return "execve";
        case 60: return "exit";
        case 61: return "wait4";
        case 62: return "kill";
        case 63: return "uname";
        case 72: return "fcntl";
        case 73: return "flock";
        case 74: return "fsync";
        case 78: return "getdents";
        case 79: return "getcwd";
        case 80: return "chdir";
        case 82: return "rename";
        case 83: return "mkdir";
        case 87: return "unlink";
        case 89: return "readlink";
        case 90: return "chmod";
        case 92: return "chown";
        case 96: return "gettimeofday";
        case 97: return "getrlimit";
        case 99: return "sysinfo";
        case 102: return "getuid";
        case 104: return "getgid";
        case 107: return "geteuid";
        case 108: return "getegid";
        case 110: return "getppid";
        case 157: return "prctl";
        case 186: return "gettid";
        case 202: return "futex";
        case 217: return "getdents64";
        case 218: return "set_tid_address";
        case 231: return "exit_group";
        case 257: return "openat";
        case 258: return "mkdirat";
        case 262: return "newfstatat";
        case 263: return "unlinkat";
        case 267: return "readlinkat";
        case 273: return "set_robust_list";
        case 288: return "accept4";
        case 293: return "pipe2";
        case 316: return "renameat2";
        case 318: return "getrandom";
        case 334: return "rseq";
        case 435: return "clone3";
        case 439: return "faccessat2";
        default: return nullptr;
    }
}
const std::map<std::string, std::string>& command_aliases() {
    static const std::map<std::string, std::string> aliases = {
        {"b", "break"}, {"c", "cont"}, {"continue", "cont"}, {"s", "step"},
        {"n", "next"}, {"ni", "next"}, {"f", "finish"}, {"i", "info"},
        {"h", "help"}, {"del", "delete"}, {"q", "quit"},
    };
    return aliases;
}
std::string command_name(const std::string& word) {
    auto found = command_aliases().find(word);
    return found == command_aliases().end() ? word : found->second;
}
void print_help(const std::string& topic) {
    if (topic.empty()) {
        std::cout <<
            "break <symbol|hex runtime address> | break file:line\n"
            "cont, si, next/ni (instruction step-over), finish, bt (frame pointers)\n"
            "where, list, step (source line; requires binutils and DWARF)\n"
            "regs [register|fp], x <address|symbol|$register> [decimal byte count], x/s <address> [max]\n"
            "set $register = <unsigned integer>; set mem <address|symbol> <hexbytes>; set disasm on|off\n"
            "watch/rwatch <address|symbol> [1|2|4|8], unwatch <id>, catch syscall [all|off|number]\n"
            "info breakpoints/watchpoints/registers/proc/sharedlibrary; info proc mappings\n"
            "delete/enable/disable <breakpoint id>, delete all, anchor, timetravel, quit\n"
            "Symbol breakpoints require code; raw addresses require an instruction boundary.\n"
            "Ctrl-C pauses a running target. Threads/fork/exec end the session safely.\n"
            "Aliases: b=break, c=cont, s=step, n=next, f=finish, i=info, h=help, del=delete.\n"
            "Type help <command> for per-command details.\n";
        return;
    }
    static const std::map<std::string, std::string> topics = {
        {"break", "break <symbol|hex runtime address> | break <file>:<line>\n"
                  "Set a software breakpoint. Symbols must resolve to code; raw addresses must point at an instruction boundary.\n"
                  "Address expressions accept symbols, $registers, 0x addresses and an optional +N/-N offset.\n"},
        {"cont", "cont (alias c)\nContinue until a breakpoint, watchpoint, captured syscall, signal or exit.\n"},
        {"si", "si\nSingle-step one instruction.\n"},
        {"next", "next / ni (alias n)\nStep over a call by running to the return address.\n"},
        {"finish", "finish (alias f)\nRun until the current function returns; requires a recognizable frame.\n"},
        {"bt", "bt\nPrint up to 64 frame-pointer backtrace frames with ELF symbols.\n"},
        {"where", "where\nShow the source location of the current instruction (requires DWARF).\n"},
        {"list", "list\nShow the source around the current instruction (requires DWARF).\n"},
        {"step", "step (alias s)\nStep one source line, executing at most 256 instructions.\n"},
        {"regs", "regs [register|fp]\nShow general registers, or FP/SIMD state for fp/xmm/ymm/st/mxcsr.\n"},
        {"x", "x <address|symbol|$register>[+/-N] [decimal byte count]\nExamine 1..4096 bytes, default 16.\n"},
        {"x/s", "x/s <address|symbol|$register>[+/-N] [decimal max bytes]\n"
                "Print a NUL-terminated string with escapes; default 128 bytes (max 4096).\n"},
        {"set", "set $register = <unsigned integer>\nset mem <address|symbol> <hexbytes>\n"
                "set disasm on|off\n"
                "Registers are decimal or 0x-hex; memory writes use raw hexadecimal bytes without 0x.\n"
                "set disasm controls the automatic 5-instruction dump after each command.\n"},
        {"watch", "watch <address|symbol> [1|2|4|8]\nSet a hardware write watchpoint (four slots, aligned address).\n"},
        {"rwatch", "rwatch <address|symbol> [1|2|4|8]\nSet a read watchpoint. x86 has no read-only watchpoint, so writes also trigger.\n"},
        {"awatch", "awatch <address|symbol> [1|2|4|8]\nSet a read/write (access) watchpoint; same encoding as rwatch.\n"},
        {"unwatch", "unwatch <watchpoint id>\nRemove a hardware watchpoint.\n"},
        {"catch", "catch syscall [all|off|decimal number]\nCapture syscall entries and exits (Linux 5.3+).\n"},
        {"info", "info breakpoints | watchpoints | registers [name] | proc [mappings] | sharedlibrary\n"
                 "Show debugger and target state.\n"},
        {"delete", "delete <id> | delete all (alias del)\nRemove software breakpoints and restore their original bytes.\n"},
        {"enable", "enable <id>\nRevalidate permissions and re-arm a disabled breakpoint.\n"},
        {"disable", "disable <id>\nRestore the original byte but keep the breakpoint metadata.\n"},
        {"anchor", "anchor\nCapture a snapshot of private writable memory, registers and FP/XSAVE state.\n"},
        {"timetravel", "timetravel\nRestore the most recent anchor; mappings must be unchanged.\n"},
        {"help", "help [command]\nShow general help or details for one command.\n"},
        {"quit", "quit / q\nExit and clean up the traced process.\n"},
    };
    auto found = topics.find(command_name(topic));
    if (found == topics.end()) throw std::runtime_error("no help for '" + topic + "'; type help");
    std::cout << found->second;
}
} // namespace

long Debugger::trace(enum __ptrace_request request, Address address, void* data) {
    errno = 0;
    long value = ptrace(request, child_, reinterpret_cast<void*>(address), data);
    if (value == -1 && errno) throw system_error("ptrace");
    return value;
}

user_regs_struct Debugger::registers() {
    user_regs_struct regs{};
    trace(PTRACE_GETREGS, 0, &regs);
    return regs;
}

void Debugger::write_byte(Address address, uint8_t byte) {
    Address aligned = address & ~(sizeof(long) - 1);
    unsigned long word = static_cast<unsigned long>(trace(PTRACE_PEEKDATA, aligned));
    auto* bytes = reinterpret_cast<uint8_t*>(&word);
    bytes[address - aligned] = byte;
    trace(PTRACE_POKEDATA, aligned, reinterpret_cast<void*>(word));
}

Debugger::ReArm::~ReArm() {
    if (!pending_ || !debugger_.alive_) return;
    try {
        debugger_.write_byte(address_, 0xcc);
    } catch (...) {
        auto bp = debugger_.breakpoints_.find(address_);
        if (bp != debugger_.breakpoints_.end()) bp->second.enabled = false;
        std::cout << "** warning: could not re-arm the breakpoint at 0x"
                  << std::hex << address_ << std::dec << "; it is now disabled.\n";
    }
}

std::vector<uint8_t> Debugger::read_memory(Address address, size_t size, bool partial) {
    if (size && address > std::numeric_limits<Address>::max() - (size - 1))
        throw std::runtime_error("memory address range overflows");
    std::vector<uint8_t> bytes;
    bytes.reserve(size);
    // Reading one machine word at a time costs a syscall per 8 bytes. Use a
    // bulk read for every size (disassembly and snapshot) and fall back to
    // ptrace for inaccessible pages or kernels that disallow bulk reads.
    if (size) {
        bytes.resize(size);
        iovec local{bytes.data(), size};
        iovec remote{reinterpret_cast<void*>(address), size};
        ssize_t count = process_vm_readv(child_, &local, 1, &remote, 1, 0);
        bytes.resize(count > 0 ? static_cast<size_t>(count) : 0);
    }
    while (bytes.size() < size) {
        Address current = address + bytes.size();
        Address aligned = current & ~(sizeof(long) - 1);
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, child_, reinterpret_cast<void*>(aligned), nullptr);
        if (word == -1 && errno) {
            if (partial) break;
            throw system_error("read memory");
        }
        size_t offset = current - aligned;
        size_t count = std::min(sizeof(long) - offset, size - bytes.size());
        auto* data = reinterpret_cast<uint8_t*>(&word);
        bytes.insert(bytes.end(), data + offset, data + offset + count);
    }
    return bytes;
}

std::vector<Debugger::Mapping> Debugger::writable_maps() {
    std::vector<Mapping> maps;
    for (const auto& map : process_maps(child_)) {
        if (map.permissions.size() != 4 || map.permissions[1] != 'w' || map.permissions[3] != 'p') continue;
        maps.push_back({map.start, map.end, map.permissions});
    }
    return maps;
}

bool Debugger::wait_stop(bool stepping) {
    for (;;) {
    int status;
    pid_t result;
    do { result = waitpid(child_, &status, 0); } while (result < 0 && errno == EINTR);
    if (result < 0) throw system_error("waitpid");
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        alive_ = false;
        interrupt_pid = 0;
        if (WIFEXITED(status)) std::cout << "** target exited with status " << WEXITSTATUS(status) << ".\n";
        else {
            std::cout << "** target terminated by signal " << WTERMSIG(status);
            if (const char* name = signal_name(WTERMSIG(status))) std::cout << " (" << name << ")";
            std::cout << ".\n";
        }
        return false;
    }
    if (!WIFSTOPPED(status)) throw std::runtime_error("unexpected process state");
    unsigned event = static_cast<unsigned>(status) >> 16;
    if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_EXEC) {
        if (event != PTRACE_EVENT_EXEC) {
            unsigned long pid = 0;
            trace(PTRACE_GETEVENTMSG, 0, &pid);
            if (!pid || pid > static_cast<unsigned long>(std::numeric_limits<pid_t>::max())) {
                cleanup();
                throw std::runtime_error("invalid child PID in ptrace event; session terminated");
            }
            descendants_.insert(static_cast<pid_t>(pid));
            std::cout << "** traced child PID: " << pid << '\n';
        }
        std::cout << "** unsupported target event: "
                  << (event == PTRACE_EVENT_EXEC ? "exec" : event == PTRACE_EVENT_CLONE ? "clone/thread" : "fork")
                  << "; ending debug session and cleaning up traced processes.\n";
        cleanup();
        return false;
    }
    syscall_stop_ = false;
    signal_ = WSTOPSIG(status);
    if (pause_requested && signal_ == SIGSTOP) {
        pause_requested = 0;
        paused_ = true;
        signal_ = 0;
        std::cout << "** target paused by Ctrl-C.\n";
        return true;
    }
    if (signal_ == (SIGTRAP | 0x80)) {
        syscall_stop_ = true;
        __ptrace_syscall_info info{};
        // 0x80 is a debugger marker, never a deliverable target signal. Clear
        // it even if the kernel cannot provide syscall info (e.g. pre-5.3).
        signal_ = 0;
        try { trace(PTRACE_GET_SYSCALL_INFO, sizeof(info), &info); }
        catch (const std::exception& error) {
            syscalls_ = false;
            throw std::runtime_error(std::string("syscall information unavailable; catching disabled: ") + error.what());
        }
        if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
            syscall_number_ = info.entry.nr;
            if (syscall_filter_ < 0 || syscall_number_ == static_cast<Address>(syscall_filter_)) {
                std::cout << "** syscall entry " << syscall_number_;
                if (const char* name = syscall_name(syscall_number_)) std::cout << " (" << name << ")";
                std::cout << " args:";
                for (auto argument : info.entry.args) std::cout << " 0x" << std::hex << argument;
                std::cout << std::dec << '\n';
                return true;
            }
        } else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
            syscall_number_ = registers().orig_rax;
            if (syscall_filter_ < 0 || syscall_number_ == static_cast<Address>(syscall_filter_)) {
                std::cout << "** syscall exit " << syscall_number_ << " result: " << info.exit.rval;
                if (const char* name = syscall_name(syscall_number_)) std::cout << " (" << name << ")";
                std::cout << '\n';
                return true;
            }
        }
        target_running = 1;
        invalidate_process_view();
        trace(PTRACE_SYSCALL);
        continue;
    }
    if (signal_ == SIGTRAP) {
        siginfo_t info{};
        trace(PTRACE_GETSIGINFO, 0, &info);
        // Single-step and a hardware data breakpoint can fire on the same
        // instruction; Linux may report TRAP_TRACE while DR6 still has B0..B3.
        if (!watches_.empty() && (info.si_code == TRAP_HWBKPT || info.si_code == TRAP_TRACE)) {
            auto status = static_cast<unsigned long>(trace(PTRACE_PEEKUSER, offsetof(user, u_debugreg) + 6 * sizeof(unsigned long)));
            trace(PTRACE_POKEUSER, offsetof(user, u_debugreg) + 6 * sizeof(unsigned long), nullptr);
            for (const auto& [slot, watch] : watches_) {
                if (status & (1ul << slot)) {
                    watch_hit_ = true;
                    std::cout << "** hit watchpoint " << watch.id << " (" << (watch.read ? "read" : "write")
                              << ") at 0x" << std::hex << watch.address << std::dec << ".\n";
                }
            }
            if (watch_hit_) { signal_ = 0; return true; }
        }
        auto regs = registers();
        auto bp = breakpoints_.find(regs.rip - 1);
        if (!stepping && (info.si_code == TRAP_BRKPT || info.si_code == SI_KERNEL) && bp != breakpoints_.end() && bp->second.enabled) {
            regs.rip--;
            trace(PTRACE_SETREGS, 0, &regs);
            write_byte(regs.rip, bp->second.original);
            if (!bp->second.internal)
                std::cout << "** hit a breakpoint at 0x" << std::hex << regs.rip << std::dec << ".\n";
            signal_ = 0;
        } else if (stepping && info.si_code == TRAP_TRACE) {
            signal_ = 0;
        }
    }
    if (signal_) {
        std::cout << "** stopped by signal " << signal_;
        if (const char* name = signal_name(signal_)) std::cout << " (" << name << ")";
        std::cout << " (forwarded on resume).\n";
    }
    return true;
    }
}

bool Debugger::single_step() {
    ExecutionScope execution;
    syscall_stop_ = false;
    watch_hit_ = false;
    paused_ = false;
    Address rip = registers().rip;
    auto bp = breakpoints_.find(rip);
    bool step_over = bp != breakpoints_.end() && bp->second.enabled && !signal_;
    std::optional<ReArm> rearm;
    if (step_over) {
        write_byte(rip, bp->second.original);
        rearm.emplace(*this, rip);
    }
    int delivered = signal_;
    signal_ = 0;
    target_running = 1;
    trace(PTRACE_SINGLESTEP, 0, reinterpret_cast<void*>(static_cast<intptr_t>(delivered)));
    return wait_stop(true);
}

void Debugger::disassemble() {
    Address rip = registers().rip;
    auto bytes = read_memory(rip, 80, true);
    for (const auto& [address, breakpoint] : breakpoints_) {
        if (breakpoint.enabled && address >= rip && address - rip < bytes.size()) bytes[address - rip] = breakpoint.original;
    }
    cs_insn* insn = nullptr;
    size_t count = cs_disasm(capstone_, bytes.data(), bytes.size(), rip, 5, &insn);
    if (!count) std::cout << "** cannot disassemble at 0x" << std::hex << rip << std::dec << ".\n";
    for (size_t i = 0; i < count; ++i) {
        std::cout << "  0x" << std::hex << insn[i].address << std::dec << ": "
                  << insn[i].mnemonic << " " << insn[i].op_str << '\n';
    }
    cs_free(insn, count);
}

void Debugger::require_executable(Address address) {
    for (const auto& map : process_maps(child_)) {
        if (address < map.start || address >= map.end) continue;
        if (map.permissions.size() == 4 && map.permissions[2] == 'x') return;
        break;
    }
    std::ostringstream message;
    message << "cannot set breakpoint at 0x" << std::hex << address
            << ": address is not in an executable mapping; "
               "use x to inspect data; watchpoints are not supported yet";
    throw std::runtime_error(message.str());
}

void Debugger::add_breakpoint(Address address, bool internal) {
    require_executable(address);
    if (breakpoints_.count(address)) {
        std::cout << "** breakpoint already exists.\n";
        return;
    }
    auto original = read_memory(address, 1)[0];
    // Allocate bookkeeping first so allocation failure cannot leave an untracked trap.
    auto inserted = breakpoints_.emplace(address, Breakpoint{internal ? 0 : next_breakpoint_id_, original, false, internal});
    try {
        write_byte(address, 0xcc);
    } catch (...) {
        breakpoints_.erase(inserted.first);
        throw;
    }
    inserted.first->second.enabled = true;
    if (internal) return;
    ++next_breakpoint_id_;
    std::cout << "** set a breakpoint at 0x" << std::hex << address << std::dec << " (id " << breakpoints_.at(address).id << ").\n";
}

void Debugger::cleanup() {
    interrupt_pid = 0;
    target_running = 0;
    // Auto-attached children may still have their initial ptrace stop pending.
    for (pid_t pid : descendants_) { if (pid > 0) kill(pid, SIGKILL); }
    if (alive_ && child_ > 0) kill(child_, SIGKILL);
    for (pid_t pid : descendants_) {
        if (pid <= 0) continue;
        int status;
        for (;;) {
            pid_t result = waitpid(pid, &status, __WALL);
            if (result < 0 && errno == EINTR) continue;
            if (result < 0 || WIFEXITED(status) || WIFSIGNALED(status)) break;
            ptrace(PTRACE_CONT, pid, nullptr, reinterpret_cast<void*>(SIGKILL));
        }
    }
    if (alive_ && child_ > 0) {
        int status;
        for (;;) {
            pid_t result = waitpid(child_, &status, __WALL);
            if (result < 0 && errno == EINTR) continue;
            if (result < 0 || WIFEXITED(status) || WIFSIGNALED(status)) break;
            ptrace(PTRACE_CONT, child_, nullptr, reinterpret_cast<void*>(SIGKILL));
        }
    }
    descendants_.clear();
    alive_ = false;
}

Debugger::~Debugger() {
    cleanup();
    if (signal_handler_installed_) sigaction(SIGINT, &old_sigint_, nullptr);
    if (capstone_) cs_close(&capstone_);
}

void Debugger::run(char** argv, const Elf64_Ehdr& elf, bool inherit_stdin) {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_) != CS_ERR_OK)
        throw std::runtime_error("cannot initialize Capstone");
    cs_option(capstone_, CS_OPT_DETAIL, CS_OPT_ON);
    symbols_.load(argv[0]);
    if (inherit_stdin) std::cout << "** warning: target and debugger share stdin; commands may be consumed by the target.\n";
    child_ = fork();
    if (child_ < 0) throw system_error("fork");
    if (!child_) {
        setpgid(0, 0);
        // The debugger ignores SIGPIPE for its own tool pipes; the target must
        // keep the default disposition across exec.
        signal(SIGPIPE, SIG_DFL);
        if (!inherit_stdin) {
            int fd = open("/dev/null", O_RDONLY);
            if (fd < 0 || dup2(fd, STDIN_FILENO) < 0) { perror("target stdin"); _exit(126); }
            if (fd != STDIN_FILENO) close(fd);
        }
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) { perror("ptrace"); _exit(126); }
        execv(argv[0], argv);
        perror("execv");
        _exit(127);
    }
    alive_ = true;
    interrupt_pid = child_;
    invalidate_process_view();
    target_running = 0;
    pause_requested = 0;
    quit_requested = 0;
    struct sigaction action{};
    action.sa_handler = on_interrupt;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, &old_sigint_) < 0) throw system_error("sigaction");
    signal_handler_installed_ = true;
    // The initial exec trap belongs to the debugger, not the target.
    int status;
    pid_t waited;
    do { waited = waitpid(child_, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited < 0) throw system_error("waitpid");
    if (!WIFSTOPPED(status)) { alive_ = false; throw std::runtime_error("target failed to start"); }
    trace(PTRACE_SETOPTIONS, 0, reinterpret_cast<void*>(PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD));
    Address entry = 0;
    std::ifstream auxv("/proc/" + std::to_string(child_) + "/auxv", std::ios::binary);
    Elf64_auxv_t aux{};
    while (auxv.read(reinterpret_cast<char*>(&aux), sizeof(aux))) {
        if (aux.a_type == AT_ENTRY) { entry = aux.a_un.a_val; break; }
    }
    if (!entry) throw std::runtime_error("cannot locate runtime entry point");
    if (registers().rip != entry) {
        add_breakpoint(entry, true);
        invalidate_process_view();
        target_running = 1;
        trace(PTRACE_CONT);
        if (!wait_stop()) return;
        target_running = 0;
        if (registers().rip != entry || signal_) throw std::runtime_error("target stopped before reaching entry point");
        breakpoints_.erase(entry);
    }
    next_breakpoint_id_ = 1;
    load_bias_ = entry - elf.e_entry;
    entry_ = entry;
    char executable_path[4096];
    ssize_t length = readlink(("/proc/" + std::to_string(child_) + "/exe").c_str(), executable_path, sizeof(executable_path));
    if (length < 0 || static_cast<size_t>(length) == sizeof(executable_path))
        throw std::runtime_error("cannot read target executable path");
    executable_.assign(executable_path, static_cast<size_t>(length));
    std::cout << "** PID: " << child_ << '\n';
    std::cout << "** program '" << argv[0] << "' loaded. entry point 0x" << std::hex << entry
              << "; load bias 0x" << entry - elf.e_entry << std::dec << ".\n";
    disassemble();
    std::string line;
    while (alive_ && !quit_requested && (std::cout << "(sdb) " << std::flush, std::getline(std::cin, line))) {
        std::istringstream input(line);
        std::vector<std::string> args;
        std::string token;
        while (input >> token) args.push_back(token);
        if (args.empty()) continue;
        try {
            const std::string command = command_name(args[0]);
            args[0] = command; // keep full-argument matchers (info, set, ...) canonical
            if (command == "help") {
                if (args.size() > 2) throw std::runtime_error("usage: help [command]");
                print_help(args.size() == 2 ? args[1] : "");
            } else if (command == "break") {
                if (args.size() != 2) throw std::runtime_error("usage: break <symbol or hex runtime address>");
                add_breakpoint(resolve_address(args[1], true));
            } else if (command == "set") {
                if (args.size() == 3 && args[1] == "disasm") {
                    if (args[2] != "on" && args[2] != "off")
                        throw std::runtime_error("usage: set disasm on|off");
                    disasm_ = args[2] == "on";
                    std::cout << "** disassembly after commands: " << (disasm_ ? "on" : "off") << ".\n";
                } else {
                    set_value(args);
                }
            } else if (command == "watch" || command == "rwatch" || command == "awatch" || command == "unwatch") {
                watch_command(args);
            } else if (command == "catch") {
                catch_command(args);
            } else if (command == "regs") {
                if (args.size() > 2) throw std::runtime_error("usage: regs [register]");
                show_registers(args.size() == 2 ? args[1] : "");
            } else if (command == "x/s") {
                if (args.size() < 2 || args.size() > 3)
                    throw std::runtime_error("usage: x/s <address|symbol|$register> [decimal max bytes]");
                uint64_t count = args.size() == 3 ? parse_number(args[2], 10) : 128;
                if (!count || count > 4096) throw std::runtime_error("max bytes must be 1..4096");
                examine_string(resolve_address(args[1]), static_cast<size_t>(count));
            } else if (command == "x") {
                if (args.size() < 2 || args.size() > 3) throw std::runtime_error("usage: x <address|symbol|$register> [decimal byte count]");
                uint64_t count = args.size() == 3 ? parse_number(args[2], 10) : 16;
                if (!count || count > 4096) throw std::runtime_error("byte count must be 1..4096");
                examine_memory(resolve_address(args[1]), count);
            } else if (command == "delete" || command == "enable" || command == "disable") {
                if (command == "delete" && args.size() == 2 && args[1] == "all") {
                    delete_all_breakpoints();
                } else {
                    if (args.size() != 2) throw std::runtime_error("usage: " + command + " <breakpoint id>");
                    uint64_t id = parse_number(args[1], 10);
                    if (!id || id > std::numeric_limits<unsigned>::max()) throw std::runtime_error("invalid breakpoint id");
                    manage_breakpoint(command, static_cast<unsigned>(id));
                }
            } else if (command == "list") {
                if (args.size() > 2) throw std::runtime_error("usage: list [line]");
                unsigned line = 0;
                if (args.size() == 2) {
                    uint64_t requested = parse_number(args[1], 10);
                    if (!requested || requested > UINT32_MAX) throw std::runtime_error("invalid source line");
                    line = static_cast<unsigned>(requested);
                }
                show_source(true, line);
            } else if (command == "info") {
                process_info(args);
            } else {
                if (args.size() != 1) throw std::runtime_error("unexpected command arguments");
                if (command == "quit" || command == "q") break;
                if (command == "si") single_step();
                else if (command == "next" || command == "ni") next_instruction();
                else if (command == "finish") finish_frame();
                else if (command == "bt") backtrace();
                else if (command == "where") show_source(false);
                else if (command == "step") source_step();
                else if (command == "cont") {
                    continue_execution();
                } else if (command == "anchor") anchor();
                else if (command == "timetravel") timetravel();
                else throw std::runtime_error("unknown command; type help");
            }
            if (alive_ && disasm_) disassemble();
        } catch (const std::exception& error) {
            std::cerr << "** error: " << error.what() << '\n';
        }
    }
}

bool Debugger::enabled_breakpoint(Address address) const {
    auto bp = breakpoints_.find(address);
    return bp != breakpoints_.end() && bp->second.enabled;
}

std::string Debugger::symbol_name(Address address) const {
    try {
        for (const auto& object : loaded_objects(child_)) {
            if (address < object.bias) continue;
            auto description = object.symbols->describe(address - object.bias);
            if (description != "??") return description;
        }
    } catch (const std::exception&) {
    }
    return {};
}

std::string Debugger::source_name(Address address) const {
    try {
        for (const auto& object : loaded_objects(child_)) {
            if (address < object.bias) continue;
            try { return source_location(object.path, address - object.bias); }
            catch (const std::exception&) { continue; }
        }
    } catch (const std::exception&) {
    }
    return {};
}

bool Debugger::mapped(Address address) const {
    for (const auto& map : process_maps(child_)) {
        if (address >= map.start && address < map.end) return true;
    }
    return false;
}

void Debugger::list_breakpoints() const {
    std::cout << "ID  State     Address\n";
    if (breakpoints_.empty()) std::cout << "** no breakpoints.\n";
    std::vector<std::pair<Address, Breakpoint>> sorted(breakpoints_.begin(), breakpoints_.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.second.id < b.second.id; });
    for (const auto& [address, bp] : sorted) {
        if (bp.internal) continue;
        std::cout << bp.id << "  " << (bp.enabled ? "enabled " : "disabled")
                  << "  0x" << std::hex << address;
        auto name = symbol_name(address);
        if (!name.empty()) std::cout << "  " << name;
        auto source = source_name(address);
        if (!source.empty()) std::cout << "  at " << source;
        std::cout << std::dec << '\n';
    }
}

void Debugger::delete_all_breakpoints() {
    unsigned removed = 0, unarmed = 0;
    for (auto it = breakpoints_.begin(); it != breakpoints_.end();) {
        auto current = it++;
        if (current->second.enabled && mapped(current->first)) {
            try { write_byte(current->first, current->second.original); }
            catch (const std::exception&) { ++unarmed; }
        }
        breakpoints_.erase(current);
        ++removed;
    }
    std::cout << "** deleted " << removed << (removed == 1 ? " breakpoint" : " breakpoints") << ".\n";
    if (unarmed) std::cout << "** warning: " << unarmed << " breakpoint(s) could not be restored.\n";
}

void Debugger::manage_breakpoint(const std::string& command, unsigned id) {
    auto found = std::find_if(breakpoints_.begin(), breakpoints_.end(),
                             [id](const auto& item) { return item.second.id == id; });
    if (found == breakpoints_.end()) throw std::runtime_error("breakpoint id not found");
    const Address address = found->first;
    auto& bp = found->second;
    if (command == "delete" || command == "disable") {
        // The mapping may have been unmapped by the target (dlclose, munmap);
        // there is no INT3 left to restore, but the metadata must stay
        // manageable instead of trapping the user forever.
        const bool present = mapped(address);
        if (bp.enabled && present) write_byte(address, bp.original);
        if (command == "delete") breakpoints_.erase(found);
        else bp.enabled = false;
        std::cout << "** breakpoint " << id << ": " << command << ".\n";
        if (!present) {
            std::cout << "** note: 0x" << std::hex << address << std::dec
                      << " is no longer mapped; only debugger metadata was updated.\n";
        }
        return;
    }
    if (!bp.enabled) {
        // Both permissions and bytes may change while the breakpoint is disabled.
        require_executable(address);
        auto original = read_memory(address, 1)[0];
        write_byte(address, 0xcc);
        bp.original = original;
        bp.enabled = true;
    }
    std::cout << "** breakpoint " << id << ": " << command << ".\n";
}

namespace {
std::map<std::string, Address> register_values(const user_regs_struct& r) {
    return {{"rax", r.rax}, {"rbx", r.rbx}, {"rcx", r.rcx}, {"rdx", r.rdx},
            {"rsi", r.rsi}, {"rdi", r.rdi}, {"rbp", r.rbp}, {"rsp", r.rsp},
            {"r8", r.r8}, {"r9", r.r9}, {"r10", r.r10}, {"r11", r.r11},
            {"r12", r.r12}, {"r13", r.r13}, {"r14", r.r14}, {"r15", r.r15},
            {"rip", r.rip}, {"eflags", r.eflags}, {"orig_rax", r.orig_rax},
            {"cs", r.cs}, {"ss", r.ss}, {"ds", r.ds}, {"es", r.es},
            {"fs", r.fs}, {"gs", r.gs}, {"fs_base", r.fs_base}, {"gs_base", r.gs_base}};
}
}

Address Debugger::resolve_address_base(const std::string& request, bool code, bool& raw) {
    if (request[0] == '$') {
        auto values = register_values(registers());
        auto found = values.find(request.substr(1));
        if (found == values.end()) throw std::runtime_error("unknown register: " + request);
        raw = true;
        return found->second;
    }
    auto colon = request.find_last_of(':');
    if (code && colon != std::string::npos && colon + 1 < request.size() &&
        request.find_first_not_of("0123456789", colon + 1) == std::string::npos)
        return resolve_source(request);
    if (symbols_.contains(request) || request.find(':') != std::string::npos)
        return resolve_symbol(request, code);
    if (request.find_first_not_of("abcdefABCDEF0123456789") == std::string::npos) {
        for (const auto& object : loaded_objects(child_)) {
            if (object.symbols->contains(request)) return resolve_symbol(request, code);
        }
    }
    bool hex = request.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
    if (hex || request.rfind("0x", 0) == 0 || request.rfind("0X", 0) == 0) {
        raw = true;
        return parse_number(request, 16);
    }
    return resolve_symbol(request, code);
}

Address Debugger::resolve_address(const std::string& value, bool code) {
    // GDB-style `*address` is accepted so `break *0x...` works as expected.
    const std::string request = (!value.empty() && value[0] == '*') ? value.substr(1) : value;
    if (request.empty()) throw std::runtime_error("missing address after '*'");
    // A trailing +N / -N (decimal or 0x hex) is an offset from a symbol,
    // register or address: `x $rsp+16`, `break main+4`, `x 0x1000-8`.
    uint64_t offset = 0;
    bool subtract = false, has_offset = false;
    size_t separator = std::string::npos;
    for (size_t i = request.size(); i > 1 && !has_offset; --i) {
        const char sign = request[i - 1];
        if (sign != '+' && sign != '-') continue;
        const std::string tail = request.substr(i);
        if (tail.empty()) continue;
        const int tail_base = tail.size() > 1 && tail[0] == '0' && (tail[1] == 'x' || tail[1] == 'X') ? 16 : 10;
        try {
            size_t consumed = 0;
            const uint64_t parsed = std::stoull(tail, &consumed, tail_base);
            if (consumed != tail.size()) continue;
            offset = parsed;
            subtract = sign == '-';
            separator = i - 1;
            has_offset = true;
        } catch (const std::exception&) {
            continue;
        }
    }
    const std::string base = has_offset ? request.substr(0, separator) : request;
    if (base.empty()) throw std::runtime_error("invalid address: " + value);
    bool raw = false;
    Address address = resolve_address_base(base, code, raw);
    if (has_offset) {
        if (subtract) {
            if (address < offset) throw std::runtime_error("address underflow: " + value);
            address -= offset;
        } else {
            if (address > UINT64_MAX - offset) throw std::runtime_error("address overflow: " + value);
            address += offset;
        }
    }
    // Symbol lookups stay silent; raw addresses, registers and offset
    // expressions cannot be checked against instruction boundaries.
    if (code && (raw || has_offset)) validate_address_breakpoint(address);
    return address;
}

void Debugger::show_registers(const std::string& name) {
    if (name == "fp" || name.rfind("xmm", 0) == 0 || name.rfind("ymm", 0) == 0 ||
        name.rfind("st", 0) == 0 || name == "mxcsr" || name == "fpcw" || name == "fpsw") {
        show_fp_register(name);
        return;
    }
    auto values = register_values(registers());
    auto print = [](const std::string& key, Address value) {
        std::cout << key << " = 0x" << std::hex << std::setw(16) << std::setfill('0')
                  << value << std::setfill(' ') << std::dec << '\n';
    };
    if (!name.empty()) {
        std::string key = name[0] == '$' ? name.substr(1) : name;
        auto found = values.find(key);
        if (found == values.end()) throw std::runtime_error("unknown register: " + name);
        print(found->first, found->second);
    } else {
        for (const auto& [key, value] : values) print(key, value);
    }
}

void Debugger::examine_string(Address address, size_t count) {
    auto bytes = read_memory(address, count, true);
    if (bytes.empty()) throw std::runtime_error("cannot read a string at this address");
    std::string text;
    bool terminated = false;
    for (uint8_t byte : bytes) {
        if (!byte) { terminated = true; break; }
        switch (byte) {
            case '\n': text += "\\n"; break;
            case '\t': text += "\\t"; break;
            case '\r': text += "\\r"; break;
            case '\\': text += "\\\\"; break;
            case '"': text += "\\\""; break;
            default:
                if (byte >= 0x20 && byte < 0x7f) text.push_back(static_cast<char>(byte));
                else {
                    char escaped[8];
                    std::snprintf(escaped, sizeof(escaped), "\\x%02x", byte);
                    text += escaped;
                }
        }
    }
    std::cout << "0x" << std::hex << address << std::dec << ": \"" << text << "\""
              << (terminated ? "" : " ... (no NUL in range)") << '\n';
}

void Debugger::examine_memory(Address address, size_t count) {
    auto bytes = read_memory(address, count);
    // Show the target's logical bytes rather than debugger-inserted INT3 traps.
    for (const auto& [bp_address, bp] : breakpoints_) {
        if (bp.enabled && bp_address >= address && bp_address - address < count)
            bytes[bp_address - address] = bp.original;
    }
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i % 16 == 0) std::cout << "0x" << std::hex << address + i << ":";
        std::cout << " " << std::hex << std::setw(2) << std::setfill('0') << unsigned(bytes[i]);
        if (i % 16 == 15 || i + 1 == bytes.size()) std::cout << '\n';
    }
    std::cout << std::setfill(' ') << std::dec;
}

Address Debugger::resolve_symbol(const std::string& request, bool code) {
    auto separator = request.find(':');
    std::string library = separator == std::string::npos ? "" : request.substr(0, separator);
    std::string name = separator == std::string::npos ? request : request.substr(separator + 1);
    struct Candidate { ElfSymbol symbol; Address bias; std::string path; };
    std::vector<Candidate> candidates;
    for (const auto& object : loaded_objects(child_)) {
        std::string base = object.path.substr(object.path.find_last_of('/') + 1);
        if (!library.empty() && library != object.path && library != base &&
            base.rfind(library + ".", 0) != 0 && base.rfind(library + "-", 0) != 0) continue;
        if (object.symbols->contains(name))
            candidates.push_back({object.symbols->resolve_typed(name), object.bias, object.path});
    }
    if (candidates.empty()) throw std::runtime_error("symbol not found in currently loaded objects: " + request +
                                                    "; the library may not be loaded or its symbols may be unavailable");
    if (candidates.size() != 1) {
        std::string message = "ambiguous symbol: " + request + "; use library:symbol; candidates:";
        for (const auto& candidate : candidates) message += " " + candidate.path + ":" + name;
        throw std::runtime_error(message);
    }
    const auto& candidate = candidates.front();
    if (candidate.symbol.type == STT_TLS || candidate.symbol.type == STT_GNU_IFUNC)
        throw std::runtime_error("TLS/IFUNC symbol resolution is not supported: " + request);
    if (code && (candidate.symbol.type == STT_OBJECT || !candidate.symbol.code))
        throw std::runtime_error("data symbols cannot be used as code breakpoints: " + request +
                                 "; use x to inspect data; watchpoints are not supported yet");
    if (candidate.symbol.value > UINT64_MAX - candidate.bias) throw std::runtime_error("symbol address overflow");
    return candidate.symbol.value + candidate.bias;
}

void Debugger::process_info(const std::vector<std::string>& args) {
    if (args.size() >= 2 && args.size() <= 3 && args[1] == "registers") {
        show_registers(args.size() == 3 ? args[2] : "");
        return;
    }
    if (args == std::vector<std::string>{"info", "breakpoints"}) { list_breakpoints(); return; }
    if (args == std::vector<std::string>{"info", "watchpoints"}) {
        for (const auto& [slot, watch] : watches_)
            std::cout << watch.id << "  0x" << std::hex << watch.address << std::dec << " size " << watch.size
                      << (watch.read ? " read" : " write") << '\n';
        if (watches_.empty()) std::cout << "** no watchpoints.\n";
    } else if (args == std::vector<std::string>{"info", "proc"}) {
        std::cout << "PID: " << child_ << "\nPPID: " << getpid() << "\nExecutable: " << executable_
                  << "\nEntry: 0x" << std::hex << entry_ << "\nLoad bias: 0x" << load_bias_ << std::dec << '\n';
    } else if (args == std::vector<std::string>{"info", "proc", "mappings"}) {
        for (const auto& map : process_maps(child_))
            std::cout << std::hex << map.start << '-' << map.end << ' ' << map.permissions
                      << ' ' << map.offset << ' ' << map.path << std::dec << '\n';
    } else if (args == std::vector<std::string>{"info", "sharedlibrary"}) {
        std::cout << "Load bias  Symbols  Object\n";
        for (const auto& object : loaded_objects(child_))
            std::cout << "0x" << std::hex << object.bias << std::dec << "  "
                      << (object.error.empty() ? (object.symbols->empty() ? "none" : "readable") : object.error) << "  " << object.path << '\n';
    } else throw std::runtime_error("usage: info breakpoints | info proc [mappings] | info sharedlibrary");
}

void Debugger::show_fp_register(const std::string& name) {
    user_fpregs_struct fp{};
    trace(PTRACE_GETFPREGS, 0, &fp);
    auto print_bytes = [](const std::string& key, const uint8_t* bytes, size_t count) {
        std::cout << key << " = 0x";
        for (size_t i = count; i > 0; --i)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << unsigned(bytes[i - 1]);
        std::cout << std::setfill(' ') << std::dec << '\n';
    };
    auto print_control = [&](const std::string& key, uint32_t value) {
        std::cout << key << " = 0x" << std::hex << value << std::dec << '\n';
    };
    if (name == "fp") {
        print_control("mxcsr", fp.mxcsr);
        print_control("fpcw", fp.cwd);
        print_control("fpsw", fp.swd);
        for (unsigned i = 0; i < 16; ++i)
            print_bytes("xmm" + std::to_string(i), reinterpret_cast<uint8_t*>(fp.xmm_space) + 16 * i, 16);
        for (unsigned i = 0; i < 8; ++i)
            print_bytes("st" + std::to_string(i), reinterpret_cast<uint8_t*>(fp.st_space) + 16 * i, 10);
        return;
    }
    if (name == "mxcsr") { print_control(name, fp.mxcsr); return; }
    if (name == "fpcw") { print_control(name, fp.cwd); return; }
    if (name == "fpsw") { print_control(name, fp.swd); return; }
    size_t prefix = name.rfind("st", 0) == 0 ? 2 : 3;
    auto index = parse_number(name.substr(prefix), 10);
    if (index >= (prefix == 2 ? 8u : 16u)) throw std::runtime_error("unknown register: " + name);
    if (prefix == 2) print_bytes(name, reinterpret_cast<uint8_t*>(fp.st_space) + 16 * index, 10);
    else if (name.rfind("xmm", 0) == 0)
        print_bytes(name, reinterpret_cast<uint8_t*>(fp.xmm_space) + 16 * index, 16);
    else {
        unsigned a, b, c, d;
        if (!__get_cpuid_count(0xD, 2, &a, &b, &c, &d) || a < 256 || !b)
            throw std::runtime_error("YMM registers are unavailable on this CPU");
        std::vector<uint8_t> xstate(65536);
        iovec buffer{xstate.data(), xstate.size()};
        trace(PTRACE_GETREGSET, NT_X86_XSTATE, &buffer);
        if (buffer.iov_len < 576 || uint64_t(b) + 256 > buffer.iov_len)
            throw std::runtime_error("YMM registers are unavailable from the kernel");
        uint64_t active, compact;
        std::memcpy(&active, xstate.data() + 512, sizeof(active));
        std::memcpy(&compact, xstate.data() + 520, sizeof(compact));
        if (compact >> 63) throw std::runtime_error("compacted XSAVE layout is not supported");
        uint8_t value[32]{};
        std::memcpy(value, reinterpret_cast<uint8_t*>(fp.xmm_space) + 16 * index, 16);
        if (active & 4) std::memcpy(value + 16, xstate.data() + b + 16 * index, 16);
        print_bytes(name, value, sizeof(value));
    }
}

void Debugger::validate_address_breakpoint(Address address) {
    require_executable(address);
    for (const auto& object : loaded_objects(child_)) {
        if (address >= object.bias && object.symbols->is_data_address(address - object.bias))
            throw std::runtime_error("known data address cannot be used as a code breakpoint; use x to inspect data");
    }
    std::cout << "** warning: address breakpoints cannot verify instruction boundaries; "
                 "ensure this address points to code, not embedded data.\n";
}

bool Debugger::continue_execution() {
    ExecutionScope execution;
    syscall_stop_ = false;
    watch_hit_ = false;
    paused_ = false;
    if (!signal_ && enabled_breakpoint(registers().rip)) {
        auto rip = registers().rip;
        auto bytes = read_memory(rip, 15, true);
        if (bytes.empty()) throw std::runtime_error("current breakpoint instruction is no longer mapped");
        bytes[0] = breakpoints_.at(rip).original;
        cs_insn* instruction = nullptr;
        auto count = cs_disasm(capstone_, bytes.data(), bytes.size(), rip, 1, &instruction);
        bool syscall = count && instruction->id == X86_INS_SYSCALL;
        cs_free(instruction, count);
        if (syscalls_ && syscall) {
            write_byte(rip, breakpoints_.at(rip).original);
            ReArm rearm(*this, rip);
            target_running = 1;
            trace(PTRACE_SYSCALL, 0, reinterpret_cast<void*>(static_cast<intptr_t>(signal_)));
            signal_ = 0;
            return wait_stop();
        }
        if (!single_step()) return false;
        if (signal_ || watch_hit_ || paused_ || pause_requested || quit_requested) {
            if (pause_requested && !paused_) std::cout << "** target pause requested by Ctrl-C.\n";
            return true;
        }
    }
    target_running = 1;
    trace(syscalls_ ? PTRACE_SYSCALL : PTRACE_CONT, 0, reinterpret_cast<void*>(static_cast<intptr_t>(signal_)));
    signal_ = 0;
    return wait_stop();
}
