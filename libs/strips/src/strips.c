#include <assert.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <stddef.h>
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
        if (!strips_should_strip(name, &shdr, policy)) { // skip current shdrstr
            continue;
        }

        shdr.sh_type = SHT_NULL;
        shdr.sh_name = 0;
        shdr.sh_offset = 0;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_size = 0;

        if (gelf_update_shdr(scn, &shdr) == 0) {
            return STRIPS_SHDR_FAILURE;
        }
    }

    return STRIPS_OK;
}

STRIPS_ERROR strips_process_file(const char *filename,
                                 const strip_policy_t policy) {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        ERROR("ELF library version mismatch");
    }

    int fd = open(filename, O_RDWR);
    if (fd < 0) {
        perror("Can't open input file decriptor");
        ERROR("open failed\n");
    }

    Elf *elf = elf_begin(fd, ELF_C_RDWR, NULL);
    if (elf == NULL) {
        perror(elf_errmsg(elf_errno()));
        ERROR("elf_begin failed\n", close(fd));
    }
    if (elf_flagelf(elf, ELF_C_SET, ELF_F_LAYOUT) == 0) {
        fprintf(stderr, "Failed to set LAYOUT flag for ELF file: %s\n",
                elf_errmsg(-1));
        return STRIPS_FAILURE;
    }

    STRIPS_ERROR_HANDLE(strips_move_sections(elf, policy));

    if (elf_update(elf, ELF_C_WRITE) < 0) {
        ERROR("elf_update failed\n", elf_end(elf), close(fd));
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