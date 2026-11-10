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
    std::map<unsigned, std::string> versions;
    for (uint64_t i = 0; i < count; ++i) {
        auto definitions = section(i);
        if (definitions.sh_type != SHT_GNU_verdef) continue;
        if (definitions.sh_link >= count) throw std::runtime_error("invalid ELF version strings");
        auto strings = section(definitions.sh_link);
        check(strings.sh_offset, strings.sh_size);
        check(definitions.sh_offset, definitions.sh_size);
        uint64_t offset = 0;
        auto version_check = [&](uint64_t position, uint64_t size) {
            if (position > definitions.sh_size || size > definitions.sh_size - position)
                throw std::runtime_error("malformed ELF version definitions");
        };
        for (uint64_t j = 0; j < definitions.sh_info; ++j) {
            version_check(offset, sizeof(Elf64_Verdef));
            Elf64_Verdef definition;
            std::memcpy(&definition, bytes.data() + definitions.sh_offset + offset, sizeof(definition));
            if (definition.vd_version != VER_DEF_CURRENT || !definition.vd_cnt)
                throw std::runtime_error("invalid ELF version definition");
            version_check(offset, definition.vd_aux);
            version_check(offset + definition.vd_aux, sizeof(Elf64_Verdaux));
            Elf64_Verdaux auxiliary;
            std::memcpy(&auxiliary, bytes.data() + definitions.sh_offset + offset + definition.vd_aux, sizeof(auxiliary));
            if (auxiliary.vda_name >= strings.sh_size) throw std::runtime_error("invalid ELF version name");
            const char* name = bytes.data() + strings.sh_offset + auxiliary.vda_name;
            if (!std::memchr(name, 0, strings.sh_size - auxiliary.vda_name))
                throw std::runtime_error("unterminated ELF version name");
            versions[definition.vd_ndx & 0x7fff] = name;
            if (j + 1 < definitions.sh_info) {
                if (definition.vd_next < sizeof(Elf64_Verdef)) throw std::runtime_error("invalid ELF version chain");
                version_check(offset, definition.vd_next);
                offset += definition.vd_next;
            }
        }
    }
    for (uint64_t i = 0; i < count; ++i) {
        auto needs = section(i);
        if (needs.sh_type != SHT_GNU_verneed) continue;
        if (needs.sh_link >= count) throw std::runtime_error("invalid ELF version requirement strings");
        auto strings = section(needs.sh_link);
        check(strings.sh_offset, strings.sh_size);
        check(needs.sh_offset, needs.sh_size);
        auto need_check = [&](uint64_t position, uint64_t size) {
            if (position > needs.sh_size || size > needs.sh_size - position)
                throw std::runtime_error("malformed ELF version requirements");
        };
        uint64_t offset = 0;
        for (uint64_t j = 0; j < needs.sh_info; ++j) {
            need_check(offset, sizeof(Elf64_Verneed));
            Elf64_Verneed need;
            std::memcpy(&need, bytes.data() + needs.sh_offset + offset, sizeof(need));
            if (need.vn_version != VER_NEED_CURRENT) throw std::runtime_error("invalid ELF version requirement");
            need_check(offset, need.vn_aux);
            uint64_t auxiliary_offset = offset + need.vn_aux;
            for (unsigned k = 0; k < need.vn_cnt; ++k) {
                need_check(auxiliary_offset, sizeof(Elf64_Vernaux));
                Elf64_Vernaux auxiliary;
                std::memcpy(&auxiliary, bytes.data() + needs.sh_offset + auxiliary_offset, sizeof(auxiliary));
                if (auxiliary.vna_name >= strings.sh_size) throw std::runtime_error("invalid ELF required version name");
                const char* name = bytes.data() + strings.sh_offset + auxiliary.vna_name;
                if (!std::memchr(name, 0, strings.sh_size - auxiliary.vna_name))
                    throw std::runtime_error("unterminated ELF required version name");
                versions[auxiliary.vna_other & 0x7fff] = name;
                if (k + 1 < need.vn_cnt) {
                    if (auxiliary.vna_next < sizeof(Elf64_Vernaux)) throw std::runtime_error("invalid ELF required version chain");
                    need_check(auxiliary_offset, auxiliary.vna_next);
                    auxiliary_offset += auxiliary.vna_next;
                }
            }
            if (j + 1 < needs.sh_info) {
                if (need.vn_next < sizeof(Elf64_Verneed)) throw std::runtime_error("invalid ELF version requirement chain");
                need_check(offset, need.vn_next);
                offset += need.vn_next;
            }
        }
    }
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
        Elf64_Shdr version_table{};
        if (table.sh_type == SHT_DYNSYM) {
            for (uint64_t j = 0; j < count; ++j) {
                auto candidate = section(j);
                if (candidate.sh_type == SHT_GNU_versym && candidate.sh_link == i) {
                    version_table = candidate;
                    check(candidate.sh_offset, candidate.sh_size);
                    if (candidate.sh_size / sizeof(Elf64_Half) < table.sh_size / sizeof(Elf64_Sym))
                        throw std::runtime_error("truncated ELF version table");
                    break;
                }
            }
        }
        for (uint64_t offset = 0; offset < table.sh_size; offset += sizeof(Elf64_Sym)) {
            Elf64_Sym symbol;
            std::memcpy(&symbol, bytes.data() + table.sh_offset + offset, sizeof(symbol));
            unsigned type = ELF64_ST_TYPE(symbol.st_info);
            if (symbol.st_shndx == SHN_UNDEF || symbol.st_shndx >= SHN_LORESERVE ||
                (type != STT_FUNC && type != STT_OBJECT && type != STT_NOTYPE && type != STT_TLS && type != STT_GNU_IFUNC)) continue;
            if (symbol.st_name >= strings.sh_size) throw std::runtime_error("invalid ELF symbol name");
            const char* name = bytes.data() + strings.sh_offset + symbol.st_name;
            if (!std::memchr(name, 0, strings.sh_size - symbol.st_name))
                throw std::runtime_error("unterminated ELF symbol name");
            if (!*name) continue;
            if (symbol.st_shndx >= count) throw std::runtime_error("invalid ELF symbol section");
            ElfSymbol entry{symbol.st_value, symbol.st_size, type,
                            (section(symbol.st_shndx).sh_flags & SHF_EXECINSTR) != 0};
            auto add = [&](const std::string& key) {
                auto& values = symbols_[key];
                if (std::none_of(values.begin(), values.end(), [&](const ElfSymbol& item) {
                        return item.value == entry.value && item.type == entry.type;
                    })) values.push_back(entry);
            };
            Elf64_Half version = 0;
            if (version_table.sh_type)
                std::memcpy(&version, bytes.data() + version_table.sh_offset +
                            offset / sizeof(Elf64_Sym) * sizeof(version), sizeof(version));
            if ((version & 0x7fff) > 1) {
                auto found = versions.find(version & 0x7fff);
                if (found == versions.end()) throw std::runtime_error("missing ELF version definition");
                add(std::string(name) + "@" + found->second);
                if (!(version & 0x8000)) add(std::string(name) + "@@" + found->second);
            }
            if (!(version & 0x8000)) add(name);
        }
    }
}

bool ElfSymbols::contains(const std::string& name) const { return symbols_.count(name) != 0; }

ElfSymbol ElfSymbols::resolve_typed(const std::string& name) const {
    auto found = symbols_.find(name);
    if (found == symbols_.end()) throw std::runtime_error("symbol not found: " + name);
    if (found->second.size() != 1) throw std::runtime_error("ambiguous symbol: " + name + "; use an address");
    return found->second.front();
}

uint64_t ElfSymbols::resolve(const std::string& name) const {
    auto symbol = resolve_typed(name);
    if (symbol.type == STT_TLS || symbol.type == STT_GNU_IFUNC)
        throw std::runtime_error("TLS/IFUNC symbol resolution is not supported: " + name);
    return symbol.value;
}

bool ElfSymbols::is_data_address(uint64_t value) const {
    for (const auto& [name, entries] : symbols_) {
        (void)name;
        for (const auto& entry : entries) {
            if (entry.type == STT_TLS || entry.type == STT_GNU_IFUNC) continue;
            if ((entry.type == STT_OBJECT || !entry.code) && value >= entry.value &&
                (value == entry.value || value - entry.value < entry.size)) return true;
        }
    }
    return false;
}

std::string ElfSymbols::describe(uint64_t value) const {
    std::string best;
    uint64_t distance = UINT64_MAX;
    for (const auto& [name, entries] : symbols_) {
        for (const auto& entry : entries) {
            if (!entry.code || entry.type == STT_OBJECT || value < entry.value) continue;
            auto delta = value - entry.value;
            if (delta && delta >= entry.size) continue;
            if (delta < distance || (delta == distance && name.size() < best.size())) {
                best = name;
                distance = delta;
            }
        }
    }
    return best.empty() ? "??" : best + "+" + std::to_string(distance);
}

std::optional<uint64_t> ElfSymbols::function_start(uint64_t value) const {
    std::optional<uint64_t> result;
    for (const auto& [name, entries] : symbols_) {
        (void)name;
        for (const auto& entry : entries) {
            if (entry.type != STT_FUNC || !entry.code || value < entry.value) continue;
            if (value != entry.value && value - entry.value >= entry.size) continue;
            if (!result || entry.value > *result) result = entry.value;
        }
    }
    return result;
}
