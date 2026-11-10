#ifndef SIMPLEDBG_SYMBOLS_H
#define SIMPLEDBG_SYMBOLS_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

// Defined ELF symbols from the main executable; values precede relocation.
class ElfSymbols {
public:
    void load(const std::string& path);
    uint64_t resolve(const std::string& name) const;
    bool contains(const std::string& name) const;
private:
    std::map<std::string, std::vector<uint64_t>> symbols_;
};

#endif
