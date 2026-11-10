#include "symbols.h"

#include <elf.h>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>

void ElfSymbols::load(const std::string& path) {
    symbols_.clear();
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("cannot open ELF symbols");
    std::vector<char> bytes((std::istreambuf_iterator<char>(file)), {});
    auto check = [&](uint64_t offset, uint64_t size) {
        if (offset > bytes.size() || size > bytes.size() - offset)
            throw std::runtime_error("malformed ELF symbol/section table");
    };
    check(0, sizeof(Elf64_Ehdr));
    Elf64_Ehdr header;
    std::memcpy(&header, bytes.data(), sizeof(header));
    if (!header.e_shoff) return; // Sectionless/stripped executables still accept addresses.
    if (header.e_shentsize != sizeof(Elf64_Shdr))
        throw std::runtime_error("invalid ELF section entry size");
    auto section = [&](uint64_t index) {
        if (index > (UINT64_MAX - header.e_shoff) / sizeof(Elf64_Shdr))
            throw std::runtime_error("ELF section offset overflow");
        uint64_t offset = header.e_shoff + index * sizeof(Elf64_Shdr);
        check(offset, sizeof(Elf64_Shdr));
        Elf64_Shdr result;
        std::memcpy(&result, bytes.data() + offset, sizeof(result));
        return result;
    };
    uint64_t count = header.e_shnum ? header.e_shnum : section(0).sh_size;
    if (count > bytes.size() / sizeof(Elf64_Shdr))
        throw std::runtime_error("invalid ELF section count");
    for (uint64_t i = 0; i < count; ++i) {
        auto table = section(i);
        if (table.sh_type != SHT_SYMTAB && table.sh_type != SHT_DYNSYM) continue;
        if (table.sh_link >= count || table.sh_entsize != sizeof(Elf64_Sym) ||
            table.sh_size % sizeof(Elf64_Sym))
            throw std::runtime_error("invalid ELF symbol table");
        auto strings = section(table.sh_link);
        if (strings.sh_type != SHT_STRTAB) throw std::runtime_error("invalid ELF string table");
        check(strings.sh_offset, strings.sh_size);
        check(table.sh_offset, table.sh_size);
        for (uint64_t offset = 0; offset < table.sh_size; offset += sizeof(Elf64_Sym)) {
            Elf64_Sym symbol;
            std::memcpy(&symbol, bytes.data() + table.sh_offset + offset, sizeof(symbol));
            unsigned type = ELF64_ST_TYPE(symbol.st_info);
            if (symbol.st_shndx == SHN_UNDEF || symbol.st_shndx >= SHN_LORESERVE ||
                (type != STT_FUNC && type != STT_OBJECT && type != STT_NOTYPE)) continue;
            if (symbol.st_name >= strings.sh_size) throw std::runtime_error("invalid ELF symbol name");
            const char* name = bytes.data() + strings.sh_offset + symbol.st_name;
            if (!std::memchr(name, 0, strings.sh_size - symbol.st_name))
                throw std::runtime_error("unterminated ELF symbol name");
            if (!*name) continue;
            auto& values = symbols_[name];
            if (std::find(values.begin(), values.end(), symbol.st_value) == values.end())
                values.push_back(symbol.st_value);
        }
    }
}

bool ElfSymbols::contains(const std::string& name) const { return symbols_.count(name) != 0; }

uint64_t ElfSymbols::resolve(const std::string& name) const {
    auto found = symbols_.find(name);
    if (found == symbols_.end()) throw std::runtime_error("symbol not found: " + name);
    if (found->second.size() != 1) throw std::runtime_error("ambiguous symbol: " + name + "; use an address");
    return found->second.front();
}
