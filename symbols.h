#ifndef SIMPLEDBG_SYMBOLS_H
#define SIMPLEDBG_SYMBOLS_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <optional>

// Defined ELF symbols from one executable or shared object; values precede relocation.
struct ElfSymbol {
    uint64_t value, size;
    unsigned type;
    bool code;
};

class ElfSymbols {
public:
    void load(const std::string& path);
    ElfSymbol resolve_typed(const std::string& name) const;
    uint64_t resolve(const std::string& name) const;
    std::optional<uint64_t> function_start(uint64_t value) const;
    std::string describe(uint64_t value) const;
    bool is_data_address(uint64_t value) const;
    bool empty() const { return symbols_.empty(); }
    bool contains(const std::string& name) const;
private:
    std::map<std::string, std::vector<ElfSymbol>> symbols_;
};

#endif
