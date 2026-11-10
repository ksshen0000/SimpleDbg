#include "sdb.h"
#include <sys/uio.h>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace {
uint64_t number(const std::string& value, int base = 0) {
    if (value.empty() || value[0] == '-' || value[0] == '+') throw std::runtime_error("expected an unsigned integer");
    if (!base) base = value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0 ? 16 : 10;
    size_t length;
    auto result = std::stoull(value, &length, base);
    if (length != value.size()) throw std::runtime_error("invalid integer: " + value);
    return result;
}
constexpr size_t snapshot_limit = 128 * 1024 * 1024;
}

void Debugger::require_writable(Address address, size_t size) {
    if (!size || address > UINT64_MAX - (size - 1)) throw std::runtime_error("invalid memory range");
    Address cursor = address;
    size_t remaining = size;
    for (const auto& map : process_maps(child_)) {
        if (cursor < map.start || cursor >= map.end) continue;
        if (map.permissions.size() != 4 || map.permissions[1] != 'w' || map.permissions[2] == 'x' || map.permissions[3] != 'p')
            throw std::runtime_error("writes require private writable non-executable memory");
        size_t count = std::min<uint64_t>(remaining, map.end - cursor);
        remaining -= count;
        if (!remaining) return;
        cursor += count;
    }
    throw std::runtime_error("memory range contains an unmapped page");
}

void Debugger::write_memory(Address address, const std::vector<uint8_t>& bytes) {
    require_writable(address, bytes.size());
    auto overlap = breakpoints_.lower_bound(address);
    if (overlap != breakpoints_.end() && overlap->first - address < bytes.size())
        throw std::runtime_error("memory write overlaps a software breakpoint; remove it first");
    if (bytes.size() > 4096) throw std::runtime_error("memory writes are limited to 4096 bytes");
    struct Word { Address address; unsigned long old_value, new_value; };
    std::vector<Word> words;
    for (size_t i = 0; i < bytes.size();) {
        Address current = address + i;
        Address aligned = current & ~Address(7);
        auto old = static_cast<unsigned long>(trace(PTRACE_PEEKDATA, aligned));
        auto value = old;
        size_t count = std::min<size_t>(8 - (current - aligned), bytes.size() - i);
        std::memcpy(reinterpret_cast<uint8_t*>(&value) + (current - aligned), bytes.data() + i, count);
        words.push_back({aligned, old, value});
        i += count;
    }
    size_t written = 0;
    try {
        for (const auto& word : words) {
            trace(PTRACE_POKEDATA, word.address, reinterpret_cast<void*>(word.new_value));
            ++written;
        }
    } catch (...) {
        try {
            while (written) {
                const auto& word = words[--written];
                trace(PTRACE_POKEDATA, word.address, reinterpret_cast<void*>(word.old_value));
            }
        } catch (...) { cleanup(); throw std::runtime_error("write rollback failed; target terminated to prevent partial-state execution"); }
        throw;
    }
}

void Debugger::set_value(const std::vector<std::string>& args) {
    if (args.size() == 4 && args[1].size() > 1 && args[1][0] == '$' && args[2] == "=") {
        auto r = registers();
        auto value = number(args[3]);
        std::string name = args[1].substr(1);
        using Field = decltype(user_regs_struct::rax) user_regs_struct::*;
        const std::map<std::string, Field> fields = {
            {"rax", &user_regs_struct::rax}, {"rbx", &user_regs_struct::rbx}, {"rcx", &user_regs_struct::rcx},
            {"rdx", &user_regs_struct::rdx}, {"rsi", &user_regs_struct::rsi}, {"rdi", &user_regs_struct::rdi},
            {"rbp", &user_regs_struct::rbp}, {"rsp", &user_regs_struct::rsp}, {"rip", &user_regs_struct::rip},
            {"r8", &user_regs_struct::r8}, {"r9", &user_regs_struct::r9}, {"r10", &user_regs_struct::r10},
            {"r11", &user_regs_struct::r11}, {"r12", &user_regs_struct::r12}, {"r13", &user_regs_struct::r13},
            {"r14", &user_regs_struct::r14}, {"r15", &user_regs_struct::r15}};
        auto field = fields.find(name);
        if (field == fields.end()) throw std::runtime_error("register is unknown or read-only");
        if (name == "rip") require_executable(value);
        r.*(field->second) = value;
        trace(PTRACE_SETREGS, 0, &r);
        std::cout << "** register updated.\n";
        return;
    }
    if (args.size() == 4 && args[1] == "mem") {
        const auto& hex = args[3];
        if (hex.empty() || hex.size() > 8192 || hex.size() % 2 || hex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
            throw std::runtime_error("hex bytes must contain 1..4096 complete bytes without separators");
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.size(); i += 2) bytes.push_back(number(hex.substr(i, 2), 16));
        auto address = resolve_address(args[2]);
        write_memory(address, bytes);
        std::cout << "** wrote " << bytes.size() << " bytes.\n";
        return;
    }
    throw std::runtime_error("usage: set $register = <unsigned value> | set mem <address|symbol> <hexbytes>");
}

Debugger::Snapshot Debugger::capture_snapshot() {
    if (signal_ || syscall_stop_ || paused_)
        throw std::runtime_error("snapshot requires a userspace breakpoint/step stop without pending signal, syscall, or Ctrl-C state");
    Snapshot next;
    next.layout = process_maps(child_);
    next.regs = registers();
    next.signal = signal_;
    next.maps = writable_maps();
    size_t total = 0;
    for (const auto& map : next.maps) {
        if (map.end - map.start > snapshot_limit - total) throw std::runtime_error("snapshot exceeds 128 MiB memory limit");
        total += map.end - map.start;
    }
    trace(PTRACE_GETFPREGS, 0, &next.fp);
    next.xstate.resize(65536);
    iovec buffer{next.xstate.data(), next.xstate.size()};
    errno = 0;
    if (ptrace(PTRACE_GETREGSET, child_, reinterpret_cast<void*>(NT_X86_XSTATE), &buffer) == -1) {
        if (errno != EIO && errno != EINVAL && errno != ENODEV) throw std::runtime_error("cannot capture XSAVE state");
        next.xstate.clear();
    } else next.xstate.resize(buffer.iov_len);
    for (const auto& map : next.maps) {
        auto bytes = read_memory(map.start, map.end - map.start);
        for (const auto& [address, breakpoint] : breakpoints_) {
            if (breakpoint.enabled && address >= map.start && address < map.end) bytes[address - map.start] = breakpoint.original;
        }
        next.memory.push_back(std::move(bytes));
    }
    next.valid = true;
    return next;
}

void Debugger::apply_snapshot(const Snapshot& snapshot) {
    for (size_t i = 0; i < snapshot.maps.size(); ++i) {
        const auto& bytes = snapshot.memory[i];
        const auto& map = snapshot.maps[i];
        for (size_t offset = 0; offset < bytes.size(); offset += 8) {
            unsigned long word;
            std::memcpy(&word, bytes.data() + offset, 8);
            for (auto bp = breakpoints_.lower_bound(map.start + offset);
                 bp != breakpoints_.end() && bp->first - (map.start + offset) < 8; ++bp) {
                if (bp->second.enabled) reinterpret_cast<uint8_t*>(&word)[bp->first - (map.start + offset)] = 0xcc;
            }
            trace(PTRACE_POKEDATA, map.start + offset, reinterpret_cast<void*>(word));
        }
    }
    // A hit breakpoint is temporarily disarmed, including in read-only text.
    // Re-arm the current set after restoring memory so rewinding cannot lose it.
    for (const auto& [address, breakpoint] : breakpoints_) {
        if (breakpoint.enabled) { require_executable(address); write_byte(address, 0xcc); }
    }
    if (!snapshot.xstate.empty()) {
        iovec buffer{const_cast<uint8_t*>(snapshot.xstate.data()), snapshot.xstate.size()};
        trace(PTRACE_SETREGSET, NT_X86_XSTATE, &buffer);
    } else trace(PTRACE_SETFPREGS, 0, const_cast<user_fpregs_struct*>(&snapshot.fp));
    trace(PTRACE_SETREGS, 0, const_cast<user_regs_struct*>(&snapshot.regs));
}

void Debugger::anchor() {
    snapshot_ = capture_snapshot();
    std::cout << "** dropped an anchor (private writable memory, GPR and FP/XSAVE state).\n";
}

void Debugger::timetravel() {
    if (!snapshot_.valid) throw std::runtime_error("no anchor has been created");
    if (process_maps(child_) != snapshot_.layout) throw std::runtime_error("memory mappings changed; cannot restore anchor");
    auto backup = capture_snapshot();
    try { apply_snapshot(snapshot_); }
    catch (...) {
        try { apply_snapshot(backup); }
        catch (...) { cleanup(); throw std::runtime_error("snapshot rollback failed; target terminated to prevent partial-state execution"); }
        throw std::runtime_error("snapshot restore failed; original stopped state was restored");
    }
    // Commit breakpoint metadata only after memory and both register sets succeed.
    for (auto& [address, breakpoint] : breakpoints_) {
        for (size_t i = 0; i < snapshot_.maps.size(); ++i) {
            auto map = snapshot_.maps[i];
            if (address >= map.start && address < map.end) breakpoint.original = snapshot_.memory[i][address - map.start];
        }
    }
    signal_ = snapshot_.signal;
    std::cout << "** go back to the anchor point.\n";
}

void Debugger::watch_command(const std::vector<std::string>& args) {
    constexpr Address debug_base = offsetof(user, u_debugreg);
    auto put = [&](unsigned index, unsigned long value) {
        trace(PTRACE_POKEUSER, debug_base + index * sizeof(unsigned long), reinterpret_cast<void*>(value));
    };
    auto control = static_cast<unsigned long>(trace(PTRACE_PEEKUSER, debug_base + 7 * sizeof(unsigned long)));
    if (args[0] == "unwatch") {
        if (args.size() != 2) throw std::runtime_error("usage: unwatch <watchpoint id>");
        auto id = number(args[1], 10);
        auto found = std::find_if(watches_.begin(), watches_.end(), [id](const auto& item) { return item.second.id == id; });
        if (found == watches_.end()) throw std::runtime_error("watchpoint id not found");
        unsigned slot = found->first;
        auto updated = control & ~(3ul << (2 * slot)) & ~(15ul << (16 + 4 * slot));
        put(7, updated);
        watches_.erase(found);
        std::cout << "** watchpoint removed.\n";
        return;
    }
    if (args.size() < 2 || args.size() > 3) throw std::runtime_error("usage: watch <address|symbol> [1|2|4|8]");
    auto size = args.size() == 3 ? number(args[2], 10) : 4;
    if (size != 1 && size != 2 && size != 4 && size != 8) throw std::runtime_error("watchpoint size must be 1, 2, 4, or 8");
    auto address = resolve_address(args[1]);
    if (address % size) throw std::runtime_error("watchpoint address must be aligned to its size");
    read_memory(address, size);
    unsigned slot = 0;
    while (slot < 4 && watches_.count(slot)) ++slot;
    if (slot == 4) throw std::runtime_error("all four hardware watchpoint slots are in use");
    unsigned length = size == 8 ? 2 : size == 4 ? 3 : size == 2 ? 1 : 0;
    auto old_address = static_cast<unsigned long>(trace(PTRACE_PEEKUSER, debug_base + slot * sizeof(unsigned long)));
    auto inserted = watches_.emplace(slot, Watchpoint{next_watch_id_, address, static_cast<size_t>(size)});
    try {
        put(slot, address);
        auto updated = control & ~(15ul << (16 + 4 * slot));
        updated |= 1ul << (2 * slot); // Local enable; write-only data watchpoint.
        updated |= static_cast<unsigned long>(1 | (length << 2)) << (16 + 4 * slot);
        put(7, updated);
    } catch (...) {
        watches_.erase(inserted.first);
        try { put(slot, old_address); put(7, control); }
        catch (...) { cleanup(); throw std::runtime_error("watchpoint rollback failed; target terminated"); }
        throw;
    }
    std::cout << "** set watchpoint " << next_watch_id_++ << " at 0x" << std::hex << address << std::dec << " size " << size << ".\n";
}

void Debugger::catch_command(const std::vector<std::string>& args) {
    if (args.size() < 2 || args.size() > 3 || args[1] != "syscall")
        throw std::runtime_error("usage: catch syscall [all|off|decimal syscall number]");
    if (args.size() == 3 && args[2] == "off") {
        syscalls_ = false;
        std::cout << "** syscall catching disabled.\n";
        return;
    }
    bool all = args.size() == 2 || args[2] == "all";
    auto filter = all ? 0 : number(args[2], 10);
    if (filter > 0x7fffffff) throw std::runtime_error("invalid syscall number");
    syscall_filter_ = all ? -1 : static_cast<int64_t>(filter);
    syscalls_ = true;
    std::cout << "** syscall catching enabled.\n";
}
