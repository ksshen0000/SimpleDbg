#include "sdb.h"
#include "source_tools.h"
#include <fstream>
#include <iostream>
#include <stdexcept>

std::pair<std::string, Address> Debugger::source_object() {
    Address rip = registers().rip;
    std::string path;
    for (const auto& map : process_maps(child_)) {
        if (map.start <= rip && rip < map.end && !map.path.empty() && map.path[0] == '/') path = map.path;
    }
    auto objects = loaded_objects(child_);
    const LoadedObject* best = nullptr;
    for (const auto& object : objects) {
        if (object.path == path && object.bias <= rip && (!best || object.bias > best->bias)) best = &object;
    }
    if (!best) throw std::runtime_error("no file-backed ELF object at current instruction");
    return {best->path, rip - best->bias};
}

void Debugger::show_source(bool listing, unsigned requested_line) {
    auto object = source_object();
    auto location = source_location(object.first, object.second);
    std::cout << location << '\n';
    if (!listing) return;
    auto colon = location.find_last_of(':');
    if (colon == std::string::npos) throw std::runtime_error("invalid source location");
    unsigned line = requested_line;
    if (!line) {
        try { line = static_cast<unsigned>(std::stoul(location.substr(colon + 1))); }
        catch (const std::exception&) { throw std::runtime_error("invalid source location"); }
    }
    const std::string path = location.substr(0, colon);
    std::ifstream file(path);
    if (!file) throw std::runtime_error("source file unavailable: " + path);
    std::string text;
    bool printed = false;
    for (unsigned i = 1; i <= line + 3 && std::getline(file, text); ++i) {
        if (i + 3 >= line) {
            std::cout << (i == line ? "> " : "  ") << i << "  " << text << '\n';
            printed = true;
        }
    }
    if (!printed) std::cout << "** source line " << line << " is not present in " << path << ".\n";
}

Address Debugger::resolve_source(const std::string& request) {
    auto colon = request.find_last_of(':');
    std::string filename = request.substr(0, colon);
    auto line = std::stoul(request.substr(colon + 1));
    if (!line || line > UINT32_MAX) throw std::runtime_error("invalid source line");
    std::vector<Address> candidates;
    for (const auto& object : loaded_objects(child_)) {
        auto addresses = source_addresses(object.path, filename, line);
        if (addresses.empty()) continue;
        // Verify the full recorded path when one was requested; decodedline
        // frequently prints basenames even for an absolute source filename.
        if (filename.find('/') != std::string::npos) {
            auto resolved = source_location(object.path, addresses.front());
            if (resolved.substr(0, resolved.find_last_of(':')) != filename) continue;
        }
        if (addresses.front() > UINT64_MAX - object.bias) throw std::runtime_error("source address overflow");
        candidates.push_back(addresses.front() + object.bias);
    }
    if (candidates.empty()) throw std::runtime_error("source line not found in loaded objects; rebuild with -g");
    if (candidates.size() != 1) throw std::runtime_error("ambiguous source file; use an absolute source path");
    return candidates.front();
}

void Debugger::source_step() {
    auto object = source_object();
    auto start = source_location(object.first, object.second);
    watch_hit_ = false;
    for (unsigned i = 0; i < 256; ++i) {
        if (!single_step()) return;
        if (signal_ || paused_ || watch_hit_ || enabled_breakpoint(registers().rip)) return;
        object = source_object();
        auto current = source_location(object.first, object.second);
        if (current != start) { std::cout << current << '\n'; return; }
    }
    std::cout << "** source step stopped after 256 instructions without a line change.\n";
}
