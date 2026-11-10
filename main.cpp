#include "sdb.h"

#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    bool inherit_stdin = argc > 1 && std::string(argv[1]) == "--inherit-stdin";
    int program = inherit_stdin ? 2 : 1;
    if (argc <= program) { std::cerr << "Usage: " << argv[0] << " [--inherit-stdin] PROGRAM [ARGS...]\n"; return 1; }
    try {
        Elf64_Ehdr elf{};
        std::ifstream file(argv[program], std::ios::binary);
        if (!file.read(reinterpret_cast<char*>(&elf), sizeof(elf)) ||
            std::memcmp(elf.e_ident, ELFMAG, SELFMAG) || elf.e_ident[EI_CLASS] != ELFCLASS64 ||
            elf.e_ident[EI_DATA] != ELFDATA2LSB || elf.e_machine != EM_X86_64 ||
            elf.e_ident[EI_VERSION] != EV_CURRENT || elf.e_version != EV_CURRENT ||
            (elf.e_type != ET_EXEC && elf.e_type != ET_DYN))
            throw std::runtime_error("expected a Linux x86-64 ELF executable");
        Debugger debugger;
        debugger.run(argv + program, elf, inherit_stdin);
    } catch (const std::exception& error) {
        std::cerr << "** error: " << error.what() << '\n';
        return 1;
    }
}
