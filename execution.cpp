#include "sdb.h"
#include "source_tools.h"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>

void Debugger::run_until(Address address, Address minimum_stack) {
    require_executable(address);
    auto original = breakpoints_.find(address);
    bool created = original == breakpoints_.end();
    bool was_disabled = !created && !original->second.enabled;
    if (created) add_breakpoint(address, true);
    else if (was_disabled) {
        write_byte(address, 0xcc);
        original->second.enabled = true;
    }
    auto remove_temporary = [&] {
        if (!alive_) {
            if (created) breakpoints_.erase(address);
            else if (was_disabled) breakpoints_.at(address).enabled = false;
            return;
        }
        auto found = breakpoints_.find(address);
        if (created || was_disabled) {
            write_byte(address, found->second.original);
            if (created) breakpoints_.erase(found);
            else found->second.enabled = false;
        }
    };
    try {
        while (continue_execution()) {
            auto r = registers();
            if (signal_ || paused_ || watch_hit_ || syscalls_) break;
            if (r.rip != address) break; // Another user breakpoint won.
            if (!created && !was_disabled) break; // Respect an existing user breakpoint.
            if (r.rsp >= minimum_stack) break;
        }
        remove_temporary();
    } catch (...) {
        try { remove_temporary(); }
        catch (...) { cleanup(); throw std::runtime_error("temporary breakpoint cleanup failed; target terminated"); }
        throw;
    }
}

void Debugger::next_instruction() {
    if (signal_) { single_step(); return; }
    auto r = registers();
    auto bytes = read_memory(r.rip, 15, true);
    if (bytes.empty()) throw std::runtime_error("current instruction is unreadable");
    if (enabled_breakpoint(r.rip)) bytes[0] = breakpoints_.at(r.rip).original;
    cs_insn* instruction = nullptr;
    size_t count = cs_disasm(capstone_, bytes.data(), bytes.size(), r.rip, 1, &instruction);
    if (!count) throw std::runtime_error("cannot decode current instruction");
    bool call = cs_insn_group(capstone_, instruction, CS_GRP_CALL);
    Address next = r.rip + instruction->size;
    cs_free(instruction, count);
    if (call) run_until(next, r.rsp);
    else single_step();
}

std::pair<Address, Address> Debugger::caller_frame(bool verify) {
    auto r = registers();
    auto bytes = read_memory(r.rip, 15, true);
    if (bytes.empty()) throw std::runtime_error("current instruction is unreadable");
    if (enabled_breakpoint(r.rip)) bytes[0] = breakpoints_.at(r.rip).original;
    cs_insn* instruction = nullptr;
    size_t count = cs_disasm(capstone_, bytes.data(), bytes.size(), r.rip, 1, &instruction);
    if (!count) throw std::runtime_error("cannot decode frame position");
    std::string mnemonic = instruction->mnemonic, operands = instruction->op_str;
    cs_free(instruction, count);
    auto word = [&](Address address) {
        Address value;
        auto data = read_memory(address, sizeof(value));
        std::memcpy(&value, data.data(), sizeof(value));
        return value;
    };
    std::optional<Address> start;
    std::string path;
    for (const auto& map : process_maps(child_)) {
        if (map.start <= r.rip && r.rip < map.end) path = map.path;
    }
    for (const auto& object : loaded_objects(child_)) {
        if (object.path != path || r.rip < object.bias) continue;
        auto candidate = object.symbols->function_start(r.rip - object.bias);
        if (candidate) start = *candidate + object.bias;
    }
    // An ENDBR can also occur at an indirect branch label inside a function.
    // For finish, only treat a known function entry as an entry stack layout.
    bool entry = !verify || (start && (r.rip == *start || (r.rip - *start == 4 && mnemonic == "push")));
    if (mnemonic == "ret" || (entry && (mnemonic == "endbr64" || (mnemonic == "push" && operands == "rbp"))))
        return {word(r.rsp), r.rbp};
    bool established = !verify;
    if (start) {
        auto prologue = read_memory(*start, std::min<Address>(64, r.rip - *start + 15), true);
        for (const auto& [address, bp] : breakpoints_) {
            if (bp.enabled && address >= *start && address - *start < prologue.size()) prologue[address - *start] = bp.original;
        }
        cs_insn* instructions = nullptr;
        auto length = cs_disasm(capstone_, prologue.data(), prologue.size(), *start, 16, &instructions);
        bool pushed = false;
        for (size_t i = 0; i < length; ++i) {
            std::string operation = instructions[i].mnemonic, operand = instructions[i].op_str;
            if (operation == "push" && operand == "rbp" && instructions[i].address < r.rip) pushed = true;
            if (pushed && operation == "mov" && operand == "rbp, rsp") {
                if (instructions[i].address == r.rip) {
                    cs_free(instructions, length);
                    return {word(r.rsp + 8), word(r.rsp)};
                }
                if (instructions[i].address < r.rip) established = true;
            }
        }
        cs_free(instructions, length);
    }
    if (!established) throw std::runtime_error("frame pointer unavailable or unverified; rebuild with -fno-omit-frame-pointer");
    for (const auto& map : process_maps(child_)) {
        if (map.start <= r.rsp && r.rsp < map.end && r.rbp >= r.rsp &&
            r.rbp < map.end && map.end - r.rbp >= 16 && !(r.rbp % 8))
            return {word(r.rbp + 8), word(r.rbp)};
    }
    throw std::runtime_error("frame pointer unavailable; rebuild with -fno-omit-frame-pointer");
}

void Debugger::finish_frame() {
    if (signal_) throw std::runtime_error("handle the pending signal before finishing a frame");
    auto r = registers();
    auto caller = caller_frame();
    require_executable(caller.first);
    run_until(caller.first, r.rsp + 8);
}

void Debugger::backtrace(unsigned max_frames) {
    auto objects = loaded_objects(child_);
    auto describe = [&](Address address) {
        for (const auto& object : objects) {
            if (address < object.bias) continue;
            auto symbol = object.symbols->describe(address - object.bias);
            if (symbol == "??") continue;
            std::string text = symbol + " (" + object.path + ")";
            // Source information is optional; frames without DWARF keep the
            // symbol-only form printed by earlier versions.
            try { text += " at " + source_location(object.path, address - object.bias); }
            catch (const std::exception&) {}
            return text;
        }
        return std::string("??");
    };
    auto r = registers();
    std::cout << "#0  0x" << std::hex << r.rip << std::dec << " " << describe(r.rip) << '\n';
    try {
        auto caller = caller_frame(false);
        Address frame = caller.second;
        std::set<Address> visited;
        for (unsigned depth = 1; depth < max_frames && caller.first; ++depth) {
            require_executable(caller.first);
            std::cout << '#' << depth << "  0x" << std::hex << caller.first << std::dec
                      << " " << describe(caller.first - 1) << '\n';
            if (!frame || !visited.insert(frame).second) break;
            bool valid = false;
            for (const auto& map : process_maps(child_)) {
                if (map.start <= r.rsp && r.rsp < map.end && frame >= r.rsp &&
                    frame < map.end && map.end - frame >= 16 && !(frame % 8)) valid = true;
            }
            if (!valid) break;
            auto data = read_memory(frame, 16);
            Address next, returned;
            std::memcpy(&next, data.data(), 8);
            std::memcpy(&returned, data.data() + 8, 8);
            if (next <= frame) break;
            frame = next;
            caller.first = returned;
        }
        std::cout << "** frame-pointer backtrace; optimized/inlined frames may be unavailable.\n";
    } catch (const std::exception& error) {
        std::cout << "** backtrace truncated: " << error.what() << '\n';
    }
}
