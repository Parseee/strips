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

bool strips_check_magic(Elf32_Ehdr *hdr) {
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

static STRIPS_ERROR strips_update_headers(Elf *in_elf, Elf *out_elf) {
    // Update ELF header
    GElf_Ehdr in_ehdr;
    if ((gelf_getehdr(in_elf, &in_ehdr)) == NULL) {
        fprintf(stderr, "gelf_getehdr failed: %s", elf_errmsg(elf_errno()));
        return STRIPS_EHDR_FAILURE;
    }

    GElf_Ehdr out_ehdr = in_ehdr;
    if (gelf_newehdr(out_elf, gelf_getclass(in_elf)) == NULL) {
        fprintf(stderr, "gelf_newehd failed: %s", elf_errmsg(elf_errno()));
        return STRIPS_EHDR_FAILURE;
    }
    if (gelf_update_ehdr(out_elf, &out_ehdr) == 0) {
        fprintf(stderr, "gelf_update_ehdr failed: %s", elf_errmsg(elf_errno()));
        return STRIPS_EHDR_FAILURE;
    }

    size_t phnum;
    if ((elf_getphdrnum(in_elf, &phnum)) != 0) {
        return STRIPS_PHNUM_FAILURE;
    }
    if ((gelf_newphdr(out_elf, phnum)) == NULL) {
        return STRIPS_PHNUM_FAILURE;
    }
    // Update each program header
    for (size_t i = 0; i < phnum; ++i) {
        GElf_Phdr phdr;
        if (gelf_getphdr(in_elf, i, &phdr) == NULL) {
            return STRIPS_PHDR_FAILURE;
        }
        if (gelf_update_phdr(out_elf, i, &phdr) == 0) {
            return STRIPS_PHDR_FAILURE;
        }
    }
    return STRIPS_OK;
}

static STRIPS_ERROR strips_setshdrstrndx(Elf *elf, size_t shdrstrndx) {
    GElf_Ehdr ehdr;
    if (gelf_getehdr(elf, &ehdr) == NULL) {
        fprintf(stderr, "gelf_getehdr failed: %s", elf_errmsg(elf_errno()));
        return STRIPS_EHDR_FAILURE;
    }
    ehdr.e_shstrndx = shdrstrndx;
    if (gelf_update_ehdr(elf, &ehdr) == 0) {
        fprintf(stderr, "gelf_update_ehdr failed: %s", elf_errmsg(elf_errno()));
        return STRIPS_EHDR_FAILURE;
    }
    return STRIPS_OK;
}

typedef struct {
    GElf_Shdr shdr;
    Elf_Scn *scn;
    char *name;
    size_t name_off;
} keep_section_t;

STRIPS_ERROR strips_move_sections(Elf *in_elf, Elf *out_elf,
                                  const strip_policy_t policy) {
    assert(in_elf);

    STRIPS_ERROR_HANDLE(strips_update_headers(in_elf, out_elf));

    size_t shdrstr_idx;
    if (elf_getshdrstrndx(in_elf, &shdrstr_idx) != 0) {
        return STRIPS_SHDR_FAILURE;
    }

    // get shstr table size
    Elf_Scn *shdrstr_sec = elf_getscn(in_elf, shdrstr_idx);
    GElf_Shdr shdrstr_shdr;
    if (gelf_getshdr(shdrstr_sec, &shdrstr_shdr) == NULL) {
        fprintf(stderr, "getshdr failed: %s\n", elf_errmsg(elf_errno()));
        return STRIPS_SHDR_FAILURE;
    }

    char *new_shdrstr = calloc(shdrstr_shdr.sh_size + 5, sizeof(*new_shdrstr));
    size_t new_shdrstr_off = 1;
    keep_section_t *keep = calloc(shdrstr_shdr.sh_size, sizeof(*keep));
    size_t keep_idx = 0;

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(in_elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if ((gelf_getshdr(scn, &shdr)) == NULL) {
            fprintf(stderr, "getshdr failed: %s\n", elf_errmsg(elf_errno()));
            continue;
        }
        char *name = elf_strptr(in_elf, shdrstr_idx, shdr.sh_name);
        if (name == NULL) {
            name = "";
        }

        // if (strips_should_strip(name, &shdr, policy) ||
        //     elf_ndxscn(scn) == shdrstr_idx) { // skip current shdrstr
        //     continue;
        // }

        // add record
        name = (name == NULL) ? "" : name;
        keep[keep_idx] = (keep_section_t){.name = name,
                                          .name_off = new_shdrstr_off,
                                          .scn = scn,
                                          .shdr = shdr};

        // copy things to new section header table
        strcpy(new_shdrstr + new_shdrstr_off, name);
        fprintf(stderr, "%s , %ld : %s\n", name, new_shdrstr_off,
                new_shdrstr + new_shdrstr_off);
        new_shdrstr_off += strlen(name) + 1;

        Elf_Scn *new_scn = elf_newscn(out_elf);
        // TODO: fix this cleanup
        if (!new_scn) {
            fprintf(stderr, "elf_newscn failed: %s\n", elf_errmsg(-1));
            free(new_shdrstr);
            for (size_t j = 0; j < keep_idx; ++j)
                free(keep[j].name);
            free(keep);
            return STRIPS_SHDR_FAILURE;
        }

        GElf_Shdr new_shdr = keep[keep_idx].shdr;
        new_shdr.sh_name = keep[keep_idx].name_off;
        new_shdr.sh_offset = 0;

        // TODO: fix this cleanup
        if (gelf_update_shdr(new_scn, &new_shdr) == 0) {
            fprintf(stderr, "gelf_update_shdr failed: %s\n", elf_errmsg(-1));
            free(new_shdrstr);
            for (size_t j = 0; j < keep_idx; ++j)
                free(keep[j].name);
            free(keep);
            return STRIPS_SHDR_FAILURE;
        }

        Elf_Data *i_data = NULL;
        while ((i_data = elf_getdata(keep[keep_idx].scn, i_data)) != NULL) {
            Elf_Data *o_data = elf_newdata(new_scn);
            // TODO: fix this cleanup
            if (!o_data) {
                fprintf(stderr, "elf_newdata failed: %s\n", elf_errmsg(-1));
                free(new_shdrstr);
                for (size_t j = 0; j < keep_idx; ++j)
                    free(keep[j].name);
                free(keep);
                return STRIPS_SHDR_FAILURE;
            }
            if (i_data->d_size > 0 && i_data->d_buf != NULL) {
                // o_data->d_buf = calloc(i_data->d_size,
                // sizeof(*o_data->d_buf)); memcpy(o_data->d_buf, i_data->d_buf,
                // i_data->d_size);
                o_data->d_buf = i_data->d_buf;
                o_data->d_size = i_data->d_size;
            } else {
                o_data->d_buf = NULL;
                o_data->d_size = 0;
            }
            o_data->d_off = i_data->d_off;
            o_data->d_align = i_data->d_align;
            o_data->d_type = i_data->d_type;
            o_data->d_version = i_data->d_version;
        }
    }

    // for (size_t i = 0; i < keep_idx; ++i) {

    // }

    Elf_Scn *new_shdrstr_scn = elf_newscn(out_elf);
    Elf_Data *new_shdrstr_scn_data = elf_newdata(new_shdrstr_scn);
    new_shdrstr_scn_data->d_buf = new_shdrstr;
    new_shdrstr_scn_data->d_size = new_shdrstr_off;
    new_shdrstr_scn_data->d_align = 1;
    new_shdrstr_scn_data->d_off = 0;
    new_shdrstr_scn_data->d_version = EV_CURRENT;

    GElf_Shdr new_shdrstr_shdr = {};
    new_shdrstr_shdr.sh_name = (GElf_Word)new_shdrstr_off;
    new_shdrstr_shdr.sh_type = SHT_STRTAB;
    new_shdrstr_shdr.sh_flags = 0;
    new_shdrstr_shdr.sh_addralign = 1;
    new_shdrstr_shdr.sh_entsize = 0;
    new_shdrstr_shdr.sh_size = new_shdrstr_off;

    if (gelf_update_shdr(new_shdrstr_scn, &new_shdrstr_shdr) == 0) {
        fprintf(stderr, "gelf_update_shdr failed: %s", elf_errmsg(elf_errno()));
        // TODO: cleanup
        return STRIPS_SHDR_FAILURE;
    }

    size_t new_shdrstrndx = elf_ndxscn(new_shdrstr_scn);
    if (new_shdrstrndx == SHN_UNDEF) {
        // TODO: fix cleanup
        fprintf(stderr, "elf_ndxscn failed for shstr\n");
        for (size_t j = 0; j < keep_idx; ++j)
            free(keep[j].name);
        free(keep);
        return STRIPS_SHDR_FAILURE;
    }

    STRIPS_ERROR_HANDLE(strips_setshdrstrndx(out_elf, new_shdrstrndx));

    // if (elf_flagelf(out_elf, ELF_C_SET, ELF_F_LAYOUT) == 0) {
    //     fprintf(stderr, "Failed to set LAYOUT flag for ELF file: %s\n",
    //             elf_errmsg(-1));
    //     return STRIPS_FAILURE;
    // }

    if (elf_update(out_elf, ELF_C_WRITE) < 0) {
        fprintf(stderr, "elf_update failed: %s\n", elf_errmsg(elf_errno()));
        exit(EXIT_FAILURE);
    }

    free(new_shdrstr);
    free(keep);

    return STRIPS_OK;
}

STRIPS_ERROR strips_process_file(const char *filename,
                                 const strip_policy_t policy) {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        ERROR("ELF library too old");
    }

    int ifd = open(filename, O_RDONLY);
    if (ifd < 0) {
        perror("Can't open input file decriptor");
        ERROR("Failed");
    }

    Elf *in_elf = elf_begin(ifd, ELF_C_READ, NULL);
    if (in_elf == NULL) {
        perror(elf_errmsg(elf_errno()));
        ERROR("elf_begin failed\n", close(ifd));
    }

    char stripped_filename[MAX_FILENAME_LEN];
    snprintf(stripped_filename, sizeof(stripped_filename), "stripped_%s",
             filename);

    int ofd = open(stripped_filename, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (ofd < 0) {
        perror("Can't open output file decriptor");
        ERROR("", elf_end(in_elf), close(ifd));
    }

    Elf *out_elf = elf_begin(ofd, ELF_C_WRITE, NULL);
    if (out_elf == NULL) {
        ERROR("The file probably exists\n", elf_end(in_elf), close(ifd),
              close(ofd));
    }

    STRIPS_ERROR_HANDLE(strips_move_sections(in_elf, out_elf, policy));

    elf_end(in_elf);
    elf_end(out_elf);

    close(ifd);
    close(ofd);
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