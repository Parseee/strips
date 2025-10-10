#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "strips.h"

#define MAX_FILENAME_LEN 256

static bool strips_should_strip(const char *name, GElf_Shdr *sec_head,
                                const strip_policy_t policy) {
    bool remove = false;
    if (!policy.debug && name && strncmp(name, ".debug", 6) == 0) {
        return true;
    }
    if (!policy.symtab && sec_head && sec_head->sh_type == SHT_SYMTAB) {
        remove = true;
    }

    return remove;
}

static bool strips_check_magic(Elf *elf) {
    if (!elf) {
        return true;
    }

    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr)) {
        char buf[256];
        strncpy(buf, elf_errmsg(elf_errno()), 255);
        ERROR(true, buf);
    }

    unsigned char *e_ident = ehdr.e_ident;
    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
        e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
        ERROR(true, "bad elf magic");
    }

    if (e_ident[EI_CLASS] != ELFCLASS32 && e_ident[EI_CLASS] != ELFCLASS64) {
        ERROR(true, "bad elf class");
    }

    if (e_ident[EI_DATA] != ELFDATA2LSB) {
        ERROR(true, "bad endianness");
    }

    if (ehdr.e_ehsize < sizeof(Elf64_Ehdr)) {
        ERROR(true, "bad elf format");
    }

    if (ehdr.e_shnum == 0 || ehdr.e_shoff == 0) {
        ERROR(true, "bad section table");
    }

    if (ehdr.e_phnum == 0 || ehdr.e_phoff == 0) {
        ERROR(true, "bad program header table");
    }

    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        ERROR(true, "bad shstrndx");
    }

    return false;
}

STRIPS_ERROR strips_move_sections(Elf *in_elf, const strip_policy_t policy) {
    assert(in_elf);

    size_t shdrstr_idx;
    if (elf_getshdrstrndx(in_elf, &shdrstr_idx) != 0) {
        return STRIPS_SHDR_FAILURE;
    }

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(in_elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if ((gelf_getshdr(scn, &shdr)) == NULL) {
            fprintf(stderr, "getshdr failed: %s\n", elf_errmsg(elf_errno()));
            continue;
        }

        char *name = elf_strptr(in_elf, shdrstr_idx, shdr.sh_name);

        if (!strips_should_strip(name, &shdr, policy)) {
            continue;
        }

        shdr.sh_type = SHT_NULL;
        shdr.sh_name = 0;
        shdr.sh_offset = 0;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_size = 0;

        if (gelf_update_shdr(scn, &shdr) == 0) {
            fprintf(stderr, "gelf_update_shdr failed: %s\n",
                    elf_errmsg(elf_errno()));
            return STRIPS_SHDR_FAILURE;
        }
    }

    return STRIPS_OK;
}

STRIPS_ERROR strips_process_file(const char *filename,
                                 const strip_policy_t policy) {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        ERROR(STRIPS_FAILURE, "ELF library version mismatch");
    }

    int fd = open(filename, O_RDWR);
    if (fd < 0) {
        perror("Can't open input file decriptor");
        ERROR(STRIPS_FAILURE, "open failed");
    }

    Elf *elf = elf_begin(fd, ELF_C_RDWR, NULL);
    if (elf == NULL) {
        perror(elf_errmsg(elf_errno()));
        ERROR(STRIPS_FAILURE, "elf_begin failed", elf_end(elf), close(fd));
    }

    if (strips_check_magic(elf)) {
        ERROR(STRIPS_FAILURE, "bad elf file", elf_end(elf), close(fd));
    }

    if (elf_flagelf(elf, ELF_C_SET, ELF_F_LAYOUT) == 0) {
        fprintf(stderr, "Failed to set LAYOUT flag for ELF file: %s\n",
                elf_errmsg(-1));
        return STRIPS_FAILURE;
    }

    STRIPS_ERROR_HANDLE(strips_move_sections(elf, policy));

    if (elf_update(elf, ELF_C_WRITE) < 0) {
        ERROR(STRIPS_FAILURE, "elf_update failed", elf_end(elf), close(fd));
    }

    elf_end(elf);
    close(fd);
    return STRIPS_OK;
}

#define CASE_ENUM_TO_STRING_(error)                                            \
    case error:                                                                \
        return #error
const char *strips_strerror(const STRIPS_ERROR error) {
    switch (error) {
        CASE_ENUM_TO_STRING_(STRIPS_OK);
        CASE_ENUM_TO_STRING_(STRIPS_FAILURE);
        CASE_ENUM_TO_STRING_(STRIPS_EHDR_FAILURE);
        CASE_ENUM_TO_STRING_(STRIPS_SHDR_FAILURE);
        CASE_ENUM_TO_STRING_(STRIPS_PHNUM_FAILURE);
        CASE_ENUM_TO_STRING_(STRIPS_PHDR_FAILURE);
    default:
        return "UNKNOWN_STRIPS_ERROR";
    }
    return "UNKNOWN_STRIPS_ERROR";
}
#undef CASE_ENUM_TO_STRING_