#include "sdb.h"

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

std::vector<uint8_t> Debugger::read_memory(Address address, size_t size, bool partial) {
    if (size && address > std::numeric_limits<Address>::max() - (size - 1))
        throw std::runtime_error("memory address range overflows");
    std::vector<uint8_t> bytes;
    bytes.reserve(size);
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
    std::ifstream file("/proc/" + std::to_string(child_) + "/maps");
    if (!file) throw std::runtime_error("cannot read process mappings");
    std::vector<Mapping> maps;
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream input(line);
        std::string range, permissions;
        input >> range >> permissions;
        if (permissions.size() != 4 || permissions[1] != 'w' || permissions[3] != 'p') continue;
        size_t dash = range.find('-');
        maps.push_back({std::stoull(range.substr(0, dash), nullptr, 16),
                        std::stoull(range.substr(dash + 1), nullptr, 16), permissions});
    }
    return maps;
}

bool Debugger::wait_stop(bool stepping) {
    int status;
    pid_t result;
    do { result = waitpid(child_, &status, 0); } while (result < 0 && errno == EINTR);
    if (result < 0) throw system_error("waitpid");
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        alive_ = false;
        if (WIFEXITED(status)) std::cout << "** target exited with status " << WEXITSTATUS(status) << ".\n";
        else std::cout << "** target terminated by signal " << WTERMSIG(status) << ".\n";
        return false;
    }
    if (!WIFSTOPPED(status)) throw std::runtime_error("unexpected process state");
    signal_ = WSTOPSIG(status);
    if (signal_ == SIGTRAP) {
        siginfo_t info{};
        trace(PTRACE_GETSIGINFO, 0, &info);
        auto regs = registers();
        auto bp = breakpoints_.find(regs.rip - 1);
        if (!stepping && (info.si_code == TRAP_BRKPT || info.si_code == SI_KERNEL) && bp != breakpoints_.end() && bp->second.enabled) {
            regs.rip--;
            trace(PTRACE_SETREGS, 0, &regs);
            write_byte(regs.rip, bp->second.original);
            std::cout << "** hit a breakpoint at 0x" << std::hex << regs.rip << std::dec << ".\n";
            signal_ = 0;
        } else if (stepping && info.si_code == TRAP_TRACE) {
            signal_ = 0;
        }
    }
    if (signal_) std::cout << "** stopped by signal " << signal_ << " (forwarded on resume).\n";
    return true;
}

bool Debugger::single_step() {
    Address rip = registers().rip;
    auto bp = breakpoints_.find(rip);
    if (bp != breakpoints_.end() && bp->second.enabled) write_byte(rip, bp->second.original);
    int delivered = signal_;
    signal_ = 0;
    trace(PTRACE_SINGLESTEP, 0, reinterpret_cast<void*>(static_cast<intptr_t>(delivered)));
    bool stopped = wait_stop(true);
    if (stopped && bp != breakpoints_.end() && bp->second.enabled) write_byte(rip, 0xcc);
    return stopped;
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

void Debugger::add_breakpoint(Address address) {
    if (breakpoints_.count(address)) {
        std::cout << "** breakpoint already exists.\n";
        return;
    }
    auto original = read_memory(address, 1)[0];
    write_byte(address, 0xcc);
    breakpoints_.emplace(address, Breakpoint{next_breakpoint_id_++, original});
    std::cout << "** set a breakpoint at 0x" << std::hex << address << std::dec << " (id " << breakpoints_.at(address).id << ").\n";
}

void Debugger::anchor() {
    Snapshot next;
    next.regs = registers();
    next.maps = writable_maps();
    next.signal = signal_;
    for (const auto& map : next.maps) {
        auto bytes = read_memory(map.start, map.end - map.start);
        for (const auto& [address, breakpoint] : breakpoints_) {
            if (breakpoint.enabled && address >= map.start && address < map.end) bytes[address - map.start] = breakpoint.original;
        }
        next.memory.push_back(std::move(bytes));
    }
    next.valid = true;
    snapshot_ = std::move(next);
    std::cout << "** dropped an anchor.\n";
}

void Debugger::timetravel() {
    if (!snapshot_.valid) throw std::runtime_error("no anchor has been created");
    if (writable_maps() != snapshot_.maps) throw std::runtime_error("memory mappings changed; cannot restore anchor");
    // Remove traps before restoring memory, then reapply the current breakpoint set.
    for (const auto& [address, breakpoint] : breakpoints_) {
        if (breakpoint.enabled) write_byte(address, breakpoint.original);
    }
    for (size_t i = 0; i < snapshot_.maps.size(); ++i) {
        const auto& bytes = snapshot_.memory[i];
        for (size_t offset = 0; offset < bytes.size(); offset += sizeof(long)) {
            long word;
            std::memcpy(&word, bytes.data() + offset, sizeof(word));
            trace(PTRACE_POKEDATA, snapshot_.maps[i].start + offset, reinterpret_cast<void*>(word));
        }
    }
    for (auto& [address, breakpoint] : breakpoints_) {
        breakpoint.original = read_memory(address, 1)[0];
        if (breakpoint.enabled) write_byte(address, 0xcc);
    }
    trace(PTRACE_SETREGS, 0, &snapshot_.regs);
    signal_ = snapshot_.signal;
    std::cout << "** go back to the anchor point.\n";
}

Debugger::~Debugger() {
    if (alive_) {
        kill(child_, SIGKILL);
        while (waitpid(child_, nullptr, 0) < 0 && errno == EINTR) {}
    }
    if (capstone_) cs_close(&capstone_);
}

void Debugger::run(char** argv, const Elf64_Ehdr& elf) {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_) != CS_ERR_OK)
        throw std::runtime_error("cannot initialize Capstone");
    symbols_.load(argv[0]);
    child_ = fork();
    if (child_ < 0) throw system_error("fork");
    if (!child_) {
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) { perror("ptrace"); _exit(126); }
        execv(argv[0], argv);
        perror("execv");
        _exit(127);
    }
    alive_ = true;
    // The initial exec trap belongs to the debugger, not the target.
    int status;
    pid_t waited;
    do { waited = waitpid(child_, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited < 0) throw system_error("waitpid");
    if (!WIFSTOPPED(status)) { alive_ = false; throw std::runtime_error("target failed to start"); }
    trace(PTRACE_SETOPTIONS, 0, reinterpret_cast<void*>(PTRACE_O_EXITKILL));
    Address entry = 0;
    std::ifstream auxv("/proc/" + std::to_string(child_) + "/auxv", std::ios::binary);
    Elf64_auxv_t aux{};
    while (auxv.read(reinterpret_cast<char*>(&aux), sizeof(aux))) {
        if (aux.a_type == AT_ENTRY) { entry = aux.a_un.a_val; break; }
    }
    if (!entry) throw std::runtime_error("cannot locate runtime entry point");
    if (registers().rip != entry) {
        add_breakpoint(entry);
        trace(PTRACE_CONT);
        if (!wait_stop()) return;
        if (registers().rip != entry || signal_) throw std::runtime_error("target stopped before reaching entry point");
        breakpoints_.erase(entry);
    }
    next_breakpoint_id_ = 1;
    load_bias_ = entry - elf.e_entry;
    std::cout << "** program '" << argv[0] << "' loaded. entry point 0x" << std::hex << entry
              << "; load bias 0x" << entry - elf.e_entry << std::dec << ".\n";
    disassemble();
    std::string line;
    while (alive_ && (std::cout << "(sdb) " << std::flush, std::getline(std::cin, line))) {
        std::istringstream input(line);
        std::vector<std::string> args;
        std::string token;
        while (input >> token) args.push_back(token);
        if (args.empty()) continue;
        try {
            const auto& command = args[0];
            if (command == "break") {
                if (args.size() != 2) throw std::runtime_error("usage: break <symbol or hex runtime address>");
                add_breakpoint(resolve_address(args[1]));
            } else if (command == "regs") {
                if (args.size() > 2) throw std::runtime_error("usage: regs [register]");
                show_registers(args.size() == 2 ? args[1] : "");
            } else if (command == "x") {
                if (args.size() < 2 || args.size() > 3) throw std::runtime_error("usage: x <address|symbol|$register> [decimal byte count]");
                uint64_t count = args.size() == 3 ? parse_number(args[2], 10) : 16;
                if (!count || count > 4096) throw std::runtime_error("byte count must be 1..4096");
                examine_memory(resolve_address(args[1]), count);
            } else if (command == "delete" || command == "enable" || command == "disable") {
                if (args.size() != 2) throw std::runtime_error("usage: " + command + " <breakpoint id>");
                uint64_t id = parse_number(args[1], 10);
                if (!id || id > std::numeric_limits<unsigned>::max()) throw std::runtime_error("invalid breakpoint id");
                manage_breakpoint(command, static_cast<unsigned>(id));
            } else if (command == "info") {
                if (args.size() != 2 || args[1] != "breakpoints") throw std::runtime_error("usage: info breakpoints");
                list_breakpoints();
            } else {
                if (args.size() != 1) throw std::runtime_error("unexpected command arguments");
                if (command == "quit" || command == "q") break;
                if (command == "si") single_step();
                else if (command == "cont") {
                    if (enabled_breakpoint(registers().rip)) {
                        if (!single_step()) continue;
                        if (signal_) { disassemble(); continue; }
                    }
                    trace(PTRACE_CONT, 0, reinterpret_cast<void*>(static_cast<intptr_t>(signal_)));
                    signal_ = 0;
                    wait_stop();
                } else if (command == "anchor") anchor();
                else if (command == "timetravel") timetravel();
                else if (command == "help") {
                    std::cout << "break <symbol|hex runtime address>, info breakpoints, delete/enable/disable <id>, "
                                 "regs [register], x <address|symbol|$register> [byte count], cont, si, anchor, timetravel, quit\n";
                } else throw std::runtime_error("unknown command; type help");
            }
            if (alive_) disassemble();
        } catch (const std::exception& error) {
            std::cerr << "** error: " << error.what() << '\n';
        }
    }
}

bool Debugger::enabled_breakpoint(Address address) const {
    auto bp = breakpoints_.find(address);
    return bp != breakpoints_.end() && bp->second.enabled;
}

void Debugger::list_breakpoints() const {
    std::cout << "ID  State     Address\n";
    if (breakpoints_.empty()) std::cout << "** no breakpoints.\n";
    for (const auto& [address, bp] : breakpoints_) {
        std::cout << bp.id << "  " << (bp.enabled ? "enabled " : "disabled")
                  << "  0x" << std::hex << address << std::dec << '\n';
    }
}

void Debugger::manage_breakpoint(const std::string& command, unsigned id) {
    auto found = std::find_if(breakpoints_.begin(), breakpoints_.end(),
                             [id](const auto& item) { return item.second.id == id; });
    if (found == breakpoints_.end()) throw std::runtime_error("breakpoint id not found");
    auto& bp = found->second;
    if (command == "delete" || command == "disable") {
        if (bp.enabled) write_byte(found->first, bp.original);
        if (command == "delete") breakpoints_.erase(found);
        else bp.enabled = false;
    } else if (!bp.enabled) {
        // Memory may have changed while the breakpoint was disabled.
        bp.original = read_memory(found->first, 1)[0];
        write_byte(found->first, 0xcc);
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

Address Debugger::resolve_address(const std::string& value) {
    if (!value.empty() && value[0] == '$') {
        auto values = register_values(registers());
        auto found = values.find(value.substr(1));
        if (found == values.end()) throw std::runtime_error("unknown register: " + value);
        return found->second;
    }
    if (symbols_.contains(value)) {
        Address offset = symbols_.resolve(value);
        if (offset > std::numeric_limits<Address>::max() - load_bias_)
            throw std::runtime_error("symbol address overflow");
        return offset + load_bias_;
    }
    bool hex = !value.empty() && value.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
    if (hex || value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0)
        return parse_number(value, 16);
    throw std::runtime_error("symbol not found: " + value + "; use a hex runtime address for stripped binaries");
}

void Debugger::show_registers(const std::string& name) {
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
