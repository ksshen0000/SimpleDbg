#ifndef SIMPLEDBG_SDB_H
#define SIMPLEDBG_SDB_H

#include "symbols.h"

#include <capstone/capstone.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include <cstddef>
#include <cstdint>
#include <map>
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
    void run(char** argv, const Elf64_Ehdr& elf);

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
    csh capstone_ = 0;
    struct Breakpoint {
        unsigned id;
        uint8_t original;
        bool enabled = true;
    };
    std::map<Address, Breakpoint> breakpoints_;
    unsigned next_breakpoint_id_ = 1;
    Address load_bias_ = 0;
    ElfSymbols symbols_;
    struct Snapshot {
        bool valid = false;
        user_regs_struct regs{};
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
    void add_breakpoint(Address address);
    void list_breakpoints() const;
    void manage_breakpoint(const std::string& command, unsigned id);
    bool enabled_breakpoint(Address address) const;
    Address resolve_address(const std::string& value);
    void show_registers(const std::string& name);
    void examine_memory(Address address, size_t count);
    void anchor();
    void timetravel();
};

#endif
