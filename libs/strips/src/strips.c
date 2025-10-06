#include <assert.h>
#include <elf.h>
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
#define MANUAL_PROGRAM_HEADER_UPDATE

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

    GElf_Ehdr *out_ehdr = NULL;
    if ((out_ehdr = gelf_newehdr(out_elf, gelf_getclass(in_elf))) == NULL) {
        fprintf(stderr, "gelf_newehd failed: %s", elf_errmsg(elf_errno()));
        return STRIPS_EHDR_FAILURE;
    }
    out_ehdr->e_machine = in_ehdr.e_machine;
    out_ehdr->e_entry = in_ehdr.e_entry;
    out_ehdr->e_type = in_ehdr.e_type;
    out_ehdr->e_flags = in_ehdr.e_flags;

    if (gelf_update_ehdr(out_elf, out_ehdr) == 0) {
        fprintf(stderr, "gelf_update_ehdr failed: %s", elf_errmsg(elf_errno()));
        return STRIPS_EHDR_FAILURE;
    }

#ifdef MANUAL_PROGRAM_HEADER_UPDATE
    size_t phnum;
    if ((elf_getphdrnum(in_elf, &phnum)) < 0) {
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
#endif
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
static STRIPS_ERROR
strips_count_stripped_shdrstr_len(Elf *elf, const size_t shdrstr_idx,
                                  size_t *new_len,
                                  const strip_policy_t policy) {
    *new_len = 1 + strlen(".shdrstr") + 1;
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        gelf_getshdr(scn, &shdr);
        char *name = elf_strptr(elf, shdrstr_idx, shdr.sh_name);
        if (strips_should_strip(name, &shdr, policy) ||
            elf_ndxscn(scn) == shdrstr_idx) {
            continue;
        }
        *new_len += strlen(name) + 1;
    }

    return STRIPS_OK;
}

static STRIPS_ERROR
strips_process_section(Elf *in_elf, Elf *out_elf, Elf_Scn *scn,
                       const size_t shdrstr_idx, const strip_policy_t policy,
                       char *new_shdrstr, size_t *new_shdrstr_off) {
    GElf_Shdr shdr;
    if ((gelf_getshdr(scn, &shdr)) == NULL) {
        fprintf(stderr, "getshdr failed: %s\n", elf_errmsg(elf_errno()));
        return STRIPS_SHDR_FAILURE;
    }
    char *name = elf_strptr(in_elf, shdrstr_idx, shdr.sh_name);

    if (strips_should_strip(name, &shdr, policy) ||
        elf_ndxscn(scn) == shdrstr_idx) { // skip current shdrstr
        return STRIPS_OK;
    }

    GElf_Shdr new_shdr = shdr;
    new_shdr.sh_name = *new_shdrstr_off;

    strcpy(new_shdrstr + *new_shdrstr_off, name);
    *new_shdrstr_off += strlen(name) + 1;

    Elf_Scn *new_scn = elf_newscn(out_elf);
    // TODO: fix this cleanup
    if (!new_scn) {
        fprintf(stderr, "elf_newscn failed: %s\n", elf_errmsg(-1));
        free(new_shdrstr);
        return STRIPS_SHDR_FAILURE;
    }

    Elf_Data *i_data = NULL;
    while ((i_data = elf_getdata(scn, i_data)) != NULL) {
        Elf_Data *o_data = elf_newdata(new_scn);

        // TODO: fix this cleanup
        if (!o_data) {
            fprintf(stderr, "elf_newdata failed: %s\n", elf_errmsg(-1));
            free(new_shdrstr);
            return STRIPS_SHDR_FAILURE;
        }

        o_data->d_size = i_data->d_size;

        o_data->d_buf = calloc(i_data->d_size, 1);
        if (i_data->d_buf != NULL) {
            memcpy(o_data->d_buf, i_data->d_buf, i_data->d_size);
        }

        // o_data->d_off = i_data->d_off;
        o_data->d_align = i_data->d_align;
        o_data->d_type = i_data->d_type;
        o_data->d_version = i_data->d_version;
        elf_flagdata(o_data, ELF_C_SET, ELF_F_DIRTY);
    }
    // TODO: fix this cleanup
    if (gelf_update_shdr(new_scn, &new_shdr) == 0) {
        fprintf(stderr, "gelf_update_shdr failed: %s\n", elf_errmsg(-1));
        free(new_shdrstr);
        return STRIPS_SHDR_FAILURE;
    }
    return STRIPS_OK;
}

static STRIPS_ERROR strips_update_shdrstr_section(
    Elf *out_elf, char *new_shdrstr, const size_t new_shdrstr_size,
    const size_t new_shdrstr_off, const size_t new_shdrstr_name) {
    Elf_Scn *new_shdrstr_scn = elf_newscn(out_elf);
    Elf_Data *new_shdrstr_scn_data = elf_newdata(new_shdrstr_scn);
    new_shdrstr_scn_data->d_buf = new_shdrstr;
    new_shdrstr_scn_data->d_size = new_shdrstr_size;
    new_shdrstr_scn_data->d_align = 1;
    new_shdrstr_scn_data->d_off = 0;
    new_shdrstr_scn_data->d_version = EV_CURRENT;

    GElf_Shdr new_shdrstr_shdr = {};
    new_shdrstr_shdr.sh_name = (GElf_Word)new_shdrstr_name;
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
        return STRIPS_SHDR_FAILURE;
    }

    STRIPS_ERROR_HANDLE(strips_setshdrstrndx(out_elf, new_shdrstrndx));

    return STRIPS_OK;
}

STRIPS_ERROR strips_move_sections(Elf *in_elf, Elf *out_elf,
                                  const strip_policy_t policy) {
    assert(in_elf);

    STRIPS_ERROR_HANDLE(strips_update_headers(in_elf, out_elf));

    size_t shdrstr_idx;
    if (elf_getshdrstrndx(in_elf, &shdrstr_idx) != 0) {
        return STRIPS_SHDR_FAILURE;
    }

    size_t new_shdrstr_size = 0;
    STRIPS_ERROR_HANDLE(strips_count_stripped_shdrstr_len(
        in_elf, shdrstr_idx, &new_shdrstr_size, policy));

    char *new_shdrstr = calloc(new_shdrstr_size, sizeof(*new_shdrstr));
    const size_t new_shdrstr_name = 1;
    strcpy(new_shdrstr + new_shdrstr_name, ".shdrstr");
    size_t new_shdrstr_off = new_shdrstr_name + strlen(".shdrstr") + 1;

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(in_elf, scn)) != NULL) {
        STRIPS_ERROR_HANDLE(
            strips_process_section(in_elf, out_elf, scn, shdrstr_idx, policy,
                                   new_shdrstr, &new_shdrstr_off));
    }

    STRIPS_ERROR_HANDLE(
        strips_update_shdrstr_section(out_elf, new_shdrstr, new_shdrstr_size,
                                      new_shdrstr_off, new_shdrstr_name));

    // if (elf_update(out_elf, ELF_C_WRITE) < 0) {
    //     fprintf(stderr, "elf_update failed: %s\n", elf_errmsg(elf_errno()));
    //     exit(EXIT_FAILURE);
    // }

    /* Now recompute PT_LOAD entries to cover SHF_ALLOC sections */
    size_t phnum = 0;
    if (elf_getphdrnum(out_elf, &phnum) < 0) {
        fprintf(stderr, "elf_getphdrnum failed: %s\n", elf_errmsg(elf_errno()));
        return STRIPS_PHNUM_FAILURE;
    }

    for (size_t pi = 0; pi < phnum; ++pi) {
        GElf_Phdr phdr;
        if (gelf_getphdr(out_elf, pi, &phdr) == NULL) {
            fprintf(stderr, "gelf_getphdr failed: %s\n",
                    elf_errmsg(elf_errno()));
            return STRIPS_PHDR_FAILURE;
        }
        // if (phdr.p_type != PT_LOAD)
        //     continue;

        /* compute new extents */
        off_t min_off = -1;
        off_t max_off = 0;
        Elf_Scn *scn = NULL;
        while ((scn = elf_nextscn(out_elf, scn)) != NULL) {
            GElf_Shdr s;
            if (gelf_getshdr(scn, &s) == NULL)
                continue;
            if (!(s.sh_flags & SHF_ALLOC))
                continue; /* only loadable sections */

            /* Use d_size/sh_size and sh_offset to detect coverage */
            if (s.sh_offset >= phdr.p_offset &&
                s.sh_offset < phdr.p_offset + phdr.p_filesz) {
                off_t scn_start = s.sh_offset;
                off_t scn_end = (off_t)(s.sh_offset + s.sh_size);
                if (min_off == -1 || scn_start < min_off)
                    min_off = scn_start;
                if (scn_end > max_off)
                    max_off = scn_end;
            }
        }

        if (min_off != -1) {
            phdr.p_offset = min_off;
            phdr.p_filesz = (GElf_Word)(max_off - min_off);
            phdr.p_memsz = phdr.p_filesz;
            /* Optionally recompute p_vaddr/p_align etc. If sh_addr values are
               set, choose p_vaddr = min(sh_addr) and p_memsz accordingly. */
            if (gelf_update_phdr(out_elf, pi, &phdr) == 0) {
                fprintf(stderr, "gelf_update_phdr failed: %s\n",
                        elf_errmsg(elf_errno()));
                return STRIPS_PHDR_FAILURE;
            }
        }
    }

    /* Finally write out with updated PHDRs */
    if (elf_update(out_elf, ELF_C_WRITE) < 0) {
        fprintf(stderr, "elf_update (final) failed: %s\n",
                elf_errmsg(elf_errno()));
        return STRIPS_FAILURE;
    }

    free(new_shdrstr);

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
    // elf_flagelf(out_elf, ELF_C_SET, ELF_F_LAYOUT);
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