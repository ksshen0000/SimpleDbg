#ifndef SIMPLEDBG_SDB_H
#define SIMPLEDBG_SDB_H

#include "symbols.h"
#include "process_maps.h"

#include <capstone/capstone.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <signal.h>
#include <set>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

using Address = uint64_t;

// Owns one traced process and its breakpoints and snapshot.
class Debugger {
public:
    Debugger() = default;
    Debugger(const Debugger&) = delete;
    Debugger& operator=(const Debugger&) = delete;
    ~Debugger();
    void run(char** argv, const Elf64_Ehdr& elf, bool inherit_stdin = false);

private:
    struct Mapping {
        Address start, end;
        std::string permissions;
        bool operator==(const Mapping& other) const {
            return start == other.start && end == other.end && permissions == other.permissions;
        }
    };

    pid_t child_ = -1;
    bool alive_ = false;
    int signal_ = 0;
    bool paused_ = false;
    bool disasm_ = true;
    csh capstone_ = 0;
    struct Breakpoint {
        unsigned id;
        uint8_t original;
        bool enabled = true;
        bool internal = false;
    };
    // Re-arms a software breakpoint whose original byte was restored for a
    // step. Its destructor runs on every exit path, including exceptions, so a
    // failed step cannot silently leave the breakpoint unarmed.
    class ReArm {
    public:
        ReArm(Debugger& debugger, Address address) : debugger_(debugger), address_(address) {}
        ~ReArm();
        ReArm(const ReArm&) = delete;
        ReArm& operator=(const ReArm&) = delete;
    private:
        Debugger& debugger_;
        Address address_;
        bool pending_ = true;
    };
    std::map<Address, Breakpoint> breakpoints_;
    unsigned next_breakpoint_id_ = 1;
    Address load_bias_ = 0;
    ElfSymbols symbols_;
    Address entry_ = 0;
    std::string executable_;
    std::set<pid_t> descendants_;
    struct sigaction old_sigint_{};
    bool signal_handler_installed_ = false;
    void cleanup();
    void process_info(const std::vector<std::string>& args);
    Address resolve_symbol(const std::string& name, bool code);
    void show_fp_register(const std::string& name);
    struct Snapshot {
        bool valid = false;
        user_regs_struct regs{};
        std::vector<uint8_t> xstate;
        user_fpregs_struct fp{};
        std::vector<ProcessMapping> layout;
        std::vector<Mapping> maps;
        std::vector<std::vector<uint8_t>> memory;
        int signal = 0;
    } snapshot_;

    long trace(enum __ptrace_request request, Address address = 0, void* data = nullptr);
    user_regs_struct registers();
    void write_byte(Address address, uint8_t byte);
    std::vector<uint8_t> read_memory(Address address, size_t size, bool partial = false);
    std::vector<Mapping> writable_maps();
    bool wait_stop(bool stepping = false);
    bool single_step();
    void disassemble();
    void validate_address_breakpoint(Address address);
    void require_executable(Address address);
    void add_breakpoint(Address address, bool internal = false);
    bool continue_execution();
    void run_until(Address address, Address minimum_stack);
    void next_instruction();
    std::pair<std::string, Address> source_object();
    void show_source(bool listing, unsigned requested_line = 0);
    Address resolve_source(const std::string& request);
    void source_step();
    void finish_frame();
    void backtrace();
    std::pair<Address, Address> caller_frame(bool verify = true);
    void set_value(const std::vector<std::string>& args);
    void write_memory(Address address, const std::vector<uint8_t>& bytes);
    void require_writable(Address address, size_t size);
    void watch_command(const std::vector<std::string>& args);
    struct Watchpoint { unsigned id; Address address; size_t size; bool read = false; };
    std::map<unsigned, Watchpoint> watches_;
    unsigned next_watch_id_ = 1;
    bool watch_hit_ = false;
    bool syscalls_ = false;
    bool syscall_stop_ = false;
    int64_t syscall_filter_ = -1;
    Address syscall_number_ = 0;
    void catch_command(const std::vector<std::string>& args);
    void list_breakpoints() const;
    void manage_breakpoint(const std::string& command, unsigned id);
    void delete_all_breakpoints();
    void set_all_breakpoints(bool enable);
    std::string symbol_name(Address address) const;
    std::string source_name(Address address) const;
    bool mapped(Address address) const;
    bool enabled_breakpoint(Address address) const;
    Address resolve_address(const std::string& value, bool code = false);
    Address resolve_address_base(const std::string& request, bool code, bool& raw);
    void show_registers(const std::string& name);
    void examine_memory(Address address, size_t count);
    void examine_string(Address address, size_t count);
    Snapshot capture_snapshot();
    void apply_snapshot(const Snapshot& snapshot);
    void anchor();
    void timetravel();
};

#endif
