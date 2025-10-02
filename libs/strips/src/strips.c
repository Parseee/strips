// #include <libelf.h>

#include "strips.h"

bool elf_check_magic(Elf32_Ehdr *hdr) {
    if (!hdr) {
        return false;
    }
    if (hdr->e_ident[EI_MAG0] != ELFMAG0) {
        ERROR("ELF Header EI_MAG0 incorrect.\n");
        return false;
    }
    if (hdr->e_ident[EI_MAG1] != ELFMAG1) {
        ERROR("ELF Header EI_MAG1 incorrect.\n");
        return false;
    }
    if (hdr->e_ident[EI_MAG2] != ELFMAG2) {
        ERROR("ELF Header EI_MAG2 incorrect.\n");
        return false;
    }
    if (hdr->e_ident[EI_MAG3] != ELFMAG3) {
        ERROR("ELF Header EI_MAG3 incorrect.\n");
        return false;
    }
    return true;
}