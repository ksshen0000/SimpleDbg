#include "sdb.h"

#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "Usage: " << argv[0] << " PROGRAM [ARGS...]\n"; return 1; }
    try {
        Elf64_Ehdr elf{};
        std::ifstream file(argv[1], std::ios::binary);
        if (!file.read(reinterpret_cast<char*>(&elf), sizeof(elf)) ||
            std::memcmp(elf.e_ident, ELFMAG, SELFMAG) || elf.e_ident[EI_CLASS] != ELFCLASS64 ||
            elf.e_ident[EI_DATA] != ELFDATA2LSB || elf.e_machine != EM_X86_64 ||
            elf.e_ident[EI_VERSION] != EV_CURRENT || elf.e_version != EV_CURRENT ||
            (elf.e_type != ET_EXEC && elf.e_type != ET_DYN))
            throw std::runtime_error("expected a Linux x86-64 ELF executable");
        Debugger debugger;
        debugger.run(argv + 1, elf);
    } catch (const std::exception& error) {
        std::cerr << "** error: " << error.what() << '\n';
        return 1;
    }
}
