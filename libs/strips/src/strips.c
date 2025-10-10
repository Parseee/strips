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

#define PAGE_ALIGN 0x10000
#define ALIGN_DOWN(x, a) ((x) & ~((a)-1))
#define ALIGN_UP(x, a) (((x) + (a)-1) & ~((a)-1))
// #define ALIGN_DOWN(x, a) (x)
// #define ALIGN_UP(x, a) (x)

static STRIPS_ERROR recompute_program_headers1(Elf *in_elf, Elf *out_elf) {
    if (!in_elf || !out_elf) {
        fprintf(stderr, "recompute_program_headers: null elf ptr\n");
        return STRIPS_FAILURE;
    }

    size_t out_phnum = 0;
    if (elf_getphdrnum(out_elf, &out_phnum) != 0) {
        fprintf(stderr, "elf_getphdrnum(out) failed: %s\n", elf_errmsg(-1));
        return STRIPS_PHNUM_FAILURE;
    }

    size_t shstrndx;
    if (elf_getshdrstrndx(out_elf, &shstrndx) != 0) {
        fprintf(stderr, "elf_getshdrstrndx(out) failed: %s\n", elf_errmsg(-1));
        return STRIPS_SHDR_FAILURE;
    }

    Elf64_Addr text_min_off = UINT64_MAX, text_max_off = 0;
    Elf64_Addr text_min_addr = UINT64_MAX, text_max_addr = 0;
    Elf64_Addr data_min_off = UINT64_MAX, data_max_off = 0;
    Elf64_Addr data_min_addr = UINT64_MAX, data_max_addr = 0;
    Elf64_Addr dyn_min_off = UINT64_MAX, dyn_max_off = 0;
    Elf64_Addr dyn_min_addr = UINT64_MAX, dyn_max_addr = 0;

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(out_elf, scn)) != NULL) {
        GElf_Shdr sh;
        if (!gelf_getshdr(scn, &sh))
            continue;

        if (!(sh.sh_flags & SHF_ALLOC))
            continue;

        const char *name = elf_strptr(out_elf, shstrndx, sh.sh_name);
        if (!name)
            continue;

        bool exec = (sh.sh_flags & SHF_EXECINSTR) != 0;
        bool write = (sh.sh_flags & SHF_WRITE) != 0;

        if (strcmp(name, ".dynamic") == 0) {
            if (sh.sh_offset < dyn_min_off)
                dyn_min_off = sh.sh_offset;
            if (sh.sh_offset + sh.sh_size > dyn_max_off)
                dyn_max_off = sh.sh_offset + sh.sh_size;
            if (sh.sh_addr < dyn_min_addr)
                dyn_min_addr = sh.sh_addr;
            if (sh.sh_addr + sh.sh_size > dyn_max_addr)
                dyn_max_addr = sh.sh_addr + sh.sh_size;
        } else if (exec || (!write && !exec)) {
            // TEXT / RO sections
            if (sh.sh_offset < text_min_off)
                text_min_off = sh.sh_offset;
            if (sh.sh_offset + sh.sh_size > text_max_off)
                text_max_off = sh.sh_offset + sh.sh_size;
            if (sh.sh_addr < text_min_addr)
                text_min_addr = sh.sh_addr;
            if (sh.sh_addr + sh.sh_size > text_max_addr)
                text_max_addr = sh.sh_addr + sh.sh_size;
        } else if (write) {
            // DATA sections
            if (sh.sh_offset < data_min_off)
                data_min_off = sh.sh_offset;
            if (sh.sh_offset + sh.sh_size > data_max_off)
                data_max_off = sh.sh_offset + sh.sh_size;
            if (sh.sh_addr < data_min_addr)
                data_min_addr = sh.sh_addr;
            if (sh.sh_addr + sh.sh_size > data_max_addr)
                data_max_addr = sh.sh_addr + sh.sh_size;
        }
    }

    Elf64_Phdr *phdr = elf64_getphdr(out_elf);
    if (!phdr) {
        fprintf(stderr, "elf64_getphdr(out) failed: %s\n", elf_errmsg(-1));
        return STRIPS_PHDR_FAILURE;
    }

    GElf_Ehdr *eh = elf64_getehdr(out_elf);
    if (!eh) {
        fprintf(stderr, "elf64_getehdr(out) failed\n");
        return STRIPS_FAILURE;
    }

    for (size_t i = 0; i < out_phnum; ++i) {
        switch (phdr[i].p_type) {
        case PT_LOAD:
            if ((phdr[i].p_flags & PF_X) || !(phdr[i].p_flags & PF_W)) {
                // TEXT segment
                if (text_min_off != UINT64_MAX) {
                    // phdr[i].p_offset =
                    ALIGN_DOWN(text_min_off, PAGE_ALIGN);
                    phdr[i].p_offset = 0;
                    // phdr[i].p_vaddr =
                    ALIGN_DOWN(text_min_addr, PAGE_ALIGN);
                    phdr[i].p_vaddr = 0;
                    phdr[i].p_paddr = phdr[i].p_vaddr;
                    phdr[i].p_filesz =
                        ALIGN_UP(text_max_off - phdr[i].p_offset, PAGE_ALIGN);
                    phdr[i].p_memsz =
                        ALIGN_UP(text_max_addr - phdr[i].p_vaddr, PAGE_ALIGN);
                    phdr[i].p_flags = PF_R | PF_X;
                    phdr[i].p_align = PAGE_ALIGN;
                }
            } else {
                // DATA segment
                if (data_min_off != UINT64_MAX) {
                    phdr[i].p_offset = ALIGN_DOWN(data_min_off, PAGE_ALIGN);
                    phdr[i].p_vaddr = ALIGN_DOWN(data_min_addr, PAGE_ALIGN);
                    phdr[i].p_paddr = phdr[i].p_vaddr;
                    phdr[i].p_filesz =
                        ALIGN_UP(data_max_off - phdr[i].p_offset, PAGE_ALIGN);
                    phdr[i].p_memsz =
                        ALIGN_UP(data_max_addr - phdr[i].p_vaddr, PAGE_ALIGN);
                    phdr[i].p_flags = PF_R | PF_W;
                    phdr[i].p_align = PAGE_ALIGN;
                }
            }
            break;

        case PT_DYNAMIC:
            if (dyn_min_off != UINT64_MAX) {
                phdr[i].p_offset = dyn_min_off;
                phdr[i].p_vaddr = dyn_min_addr;
                phdr[i].p_paddr = phdr[i].p_vaddr;
                phdr[i].p_filesz = dyn_max_off - dyn_min_off;
                phdr[i].p_memsz = dyn_max_addr - dyn_min_addr;
                phdr[i].p_flags = PF_R | PF_W;
                phdr[i].p_align = sizeof(Elf64_Addr);
            }
            break;

        case PT_PHDR:
            phdr[i].p_offset = eh->e_phoff;
            phdr[i].p_vaddr = 0;
            phdr[i].p_paddr = 0;
            phdr[i].p_filesz = elf64_fsize(ELF_T_PHDR, out_phnum, EV_CURRENT);
            phdr[i].p_memsz = phdr[i].p_filesz;
            phdr[i].p_flags = PF_R;
            phdr[i].p_align = sizeof(Elf64_Addr);
            break;

        case PT_INTERP: {
            Elf_Scn *s = NULL;
            while ((s = elf_nextscn(out_elf, s)) != NULL) {
                GElf_Shdr sh;
                if (!gelf_getshdr(s, &sh))
                    continue;
                const char *nm = elf_strptr(out_elf, shstrndx, sh.sh_name);
                if (nm && strcmp(nm, ".interp") == 0) {
                    phdr[i].p_offset = sh.sh_offset;
                    phdr[i].p_vaddr = sh.sh_addr;
                    phdr[i].p_paddr = sh.sh_addr;
                    phdr[i].p_filesz = sh.sh_size;
                    phdr[i].p_memsz = sh.sh_size;
                    phdr[i].p_flags = PF_R;
                    phdr[i].p_align = 0x1;
                    break;
                }
            }
            break;
        }

        case PT_GNU_RELRO:
            if (data_min_off != UINT64_MAX) {
                phdr[i].p_offset = ALIGN_DOWN(data_min_off, 0x1);
                phdr[i].p_vaddr = ALIGN_DOWN(data_min_addr, 0x1);
                phdr[i].p_paddr = phdr[i].p_vaddr;
                // RELRO size = from start of data to end of read-only
                phdr[i].p_filesz =
                    ALIGN_UP(data_max_off - phdr[i].p_offset, 0x1);
                phdr[i].p_memsz = phdr[i].p_filesz;
                phdr[i].p_flags = PF_R;
                phdr[i].p_align = 0x1;
            }
            break;

        default:
            break;
        }
    }

    elf_flagphdr(out_elf, ELF_C_SET, ELF_F_DIRTY);
    return STRIPS_OK;
}

static STRIPS_ERROR recompute_program_headers(Elf *in_elf, Elf *out_elf) {
    if (!in_elf || !out_elf) {
        fprintf(stderr, "recompute_program_headers: null elf ptr\n");
        return STRIPS_FAILURE;
    }

    size_t out_phnum = 0;
    if (elf_getphdrnum(out_elf, &out_phnum) != 0) {
        fprintf(stderr, "elf_getphdrnum(out) failed: %s\n", elf_errmsg(-1));
        return STRIPS_PHNUM_FAILURE;
    }

    size_t shstrndx;
    if (elf_getshdrstrndx(out_elf, &shstrndx) != 0) {
        fprintf(stderr, "elf_getshdrstrndx(out) failed: %s\n", elf_errmsg(-1));
        return STRIPS_SHDR_FAILURE;
    }

    Elf64_Phdr *phdr = elf64_getphdr(out_elf);
    if (!phdr) {
        fprintf(stderr, "elf64_getphdr(out) failed: %s\n", elf_errmsg(-1));
        return STRIPS_PHDR_FAILURE;
    }

    GElf_Ehdr *eh = elf64_getehdr(out_elf);
    if (!eh) {
        fprintf(stderr, "elf64_getehdr(out) failed\n");
        return STRIPS_FAILURE;
    }

/* helper: check name against NULL-terminated list */
#define MATCH_NAME_IN_LIST(n, list)                                            \
    ({                                                                         \
        const char *___n = (n);                                                \
        bool ___m = false;                                                     \
        if (___n) {                                                            \
            for (const char *const *___p = (list); *___p != NULL; ++___p) {    \
                if (strcmp(___n, *___p) == 0) {                                \
                    ___m = true;                                               \
                    break;                                                     \
                }                                                              \
            }                                                                  \
        }                                                                      \
        ___m;                                                                  \
    })

    /* section name lists -- extend these lists to taste */
    const char *dynamic_names[] = {".dynamic", NULL};

    const char *interp_names[] = {".interp", NULL};

    const char *note_names[] = {".note.gnu.build-id", ".note.ABI-tag", NULL};

    const char *ehframe_names[] = {".eh_frame_hdr", NULL};

    const char *relro_names[] = {".dynamic", ".got", ".init_array",
                                 ".fini_array", NULL};

    const char *text_like_names[] = {".interp",
                                     ".note.gnu.build-id",
                                     ".note.ABI-tag",
                                     ".gnu.hash",
                                     ".dynsym",
                                     ".dynstr",
                                     ".gnu.version",
                                     ".gnu.version_r",
                                     ".rela.dyn",
                                     ".rela.plt",
                                     ".init",
                                     ".plt",
                                     ".text",
                                     ".fini",
                                     ".rodata",
                                     ".plt.got",
                                     ".plt.sec",
                                     ".gcc_except_table",
                                     ".eh_frame_hdr",
                                     ".eh_frame",
                                     NULL};

    const char *data_like_names[] = {
        ".init_array", ".fini_array", ".dynamic", ".data", ".bss",
        ".got",        ".got.plt",    ".tdata",   ".tbss", NULL};

    /* iterate headers */
    for (size_t i = 0; i < out_phnum; ++i) {
        Elf64_Addr min_off = UINT64_MAX, max_off = 0;
        Elf64_Addr min_addr = UINT64_MAX, max_addr = 0;
        bool any = false;

        switch (phdr[i].p_type) {
        case PT_LOAD: {
            bool is_text =
                (phdr[i].p_flags & PF_X) || !(phdr[i].p_flags & PF_W);

            Elf_Scn *s = NULL;
            while ((s = elf_nextscn(out_elf, s)) != NULL) {
                GElf_Shdr sh;
                if (!gelf_getshdr(s, &sh))
                    continue;

                /* only consider alloc sections */
                if (!(sh.sh_flags & SHF_ALLOC))
                    continue;

                const char *name = elf_strptr(out_elf, shstrndx, sh.sh_name);
                if (!name)
                    continue;

                bool include = false;

                if (is_text) {
                    if (MATCH_NAME_IN_LIST(name, text_like_names))
                        include = true;
                    else if (!(sh.sh_flags & SHF_WRITE))
                        include = true;
                } else {
                    if (MATCH_NAME_IN_LIST(name, data_like_names))
                        include = true;
                    else if (sh.sh_flags & SHF_WRITE)
                        include = true;
                }

                if (!include)
                    continue;

                /* track bounds */
                any = true;
                if (sh.sh_offset < min_off)
                    min_off = sh.sh_offset;
                if (sh.sh_offset + sh.sh_size > max_off)
                    max_off = sh.sh_offset + sh.sh_size;
                if (sh.sh_addr < min_addr)
                    min_addr = sh.sh_addr;
                if (sh.sh_addr + sh.sh_size > max_addr)
                    max_addr = sh.sh_addr + sh.sh_size;
            }

            if (any) {
                /* PT_LOADs must be page-aligned for the kernel */
                phdr[i].p_offset =
                    (is_text) ? 0 : ALIGN_DOWN(min_off, PAGE_ALIGN);
                phdr[i].p_vaddr =
                    (is_text) ? 0 : ALIGN_DOWN(min_addr, PAGE_ALIGN);
                phdr[i].p_paddr = phdr[i].p_vaddr;
                phdr[i].p_filesz =
                    ALIGN_UP(max_off - phdr[i].p_offset, PAGE_ALIGN);
                phdr[i].p_memsz =
                    ALIGN_UP(max_addr - phdr[i].p_vaddr, PAGE_ALIGN);
                /* preserve execute/write flags but ensure readable */
                phdr[i].p_flags = (phdr[i].p_flags & (PF_X | PF_W)) | PF_R;
                phdr[i].p_align = PAGE_ALIGN;
            } else {
                /* no matching sections: zero it out (optional) */
                phdr[i].p_offset = 0;
                phdr[i].p_vaddr = 0;
                phdr[i].p_paddr = 0;
                phdr[i].p_filesz = 0;
                phdr[i].p_memsz = 0;
                phdr[i].p_flags = 0;
                phdr[i].p_align = 0;
            }
        } break;

        case PT_DYNAMIC:
            /* include only dynamic-related sections; keep PT_DYNAMIC narrow (no
             * page-align) */
            {
                Elf_Scn *s = NULL;
                while ((s = elf_nextscn(out_elf, s)) != NULL) {
                    GElf_Shdr sh;
                    if (!gelf_getshdr(s, &sh))
                        continue;

                    if (!(sh.sh_flags & SHF_ALLOC))
                        continue;

                    const char *name =
                        elf_strptr(out_elf, shstrndx, sh.sh_name);
                    if (!name)
                        continue;

                    if (!MATCH_NAME_IN_LIST(name, dynamic_names))
                        continue;

                    any = true;
                    if (sh.sh_offset < min_off)
                        min_off = sh.sh_offset;
                    if (sh.sh_offset + sh.sh_size > max_off)
                        max_off = sh.sh_offset + sh.sh_size;
                    if (sh.sh_addr < min_addr)
                        min_addr = sh.sh_addr;
                    if (sh.sh_addr + sh.sh_size > max_addr)
                        max_addr = sh.sh_addr + sh.sh_size;
                }

                if (any) {
                    /* keep exact .dynamic bounds (no ALIGN_DOWN) and small
                     * alignment */
                    phdr[i].p_offset = min_off;
                    phdr[i].p_vaddr = min_addr;
                    phdr[i].p_paddr = phdr[i].p_vaddr;
                    phdr[i].p_filesz = (max_off - min_off);
                    phdr[i].p_memsz = (max_addr - min_addr);
                    phdr[i].p_flags = PF_R | PF_W; /* dynamic is usually RW */
                    phdr[i].p_align = sizeof(Elf64_Addr);
                } else {
                    phdr[i].p_offset = 0;
                    phdr[i].p_vaddr = 0;
                    phdr[i].p_paddr = 0;
                    phdr[i].p_filesz = 0;
                    phdr[i].p_memsz = 0;
                    phdr[i].p_flags = 0;
                    phdr[i].p_align = 0;
                }
            }
            break;

        case PT_INTERP: {
            Elf_Scn *s = NULL;
            while ((s = elf_nextscn(out_elf, s)) != NULL) {
                GElf_Shdr sh;
                if (!gelf_getshdr(s, &sh))
                    continue;
                const char *name = elf_strptr(out_elf, shstrndx, sh.sh_name);
                if (!name)
                    continue;
                if (!MATCH_NAME_IN_LIST(name, interp_names))
                    continue;

                any = true;
                if (sh.sh_offset < min_off)
                    min_off = sh.sh_offset;
                if (sh.sh_offset + sh.sh_size > max_off)
                    max_off = sh.sh_offset + sh.sh_size;
                if (sh.sh_addr < min_addr)
                    min_addr = sh.sh_addr;
                if (sh.sh_addr + sh.sh_size > max_addr)
                    max_addr = sh.sh_addr + sh.sh_size;
            }

            if (any) {
                phdr[i].p_offset = min_off;
                phdr[i].p_vaddr = min_addr;
                phdr[i].p_paddr = phdr[i].p_vaddr;
                phdr[i].p_filesz = (max_off - min_off);
                phdr[i].p_memsz = (max_addr - min_addr);
                phdr[i].p_flags = PF_R;
                phdr[i].p_align = 1;
            } else {
                phdr[i].p_offset = 0;
                phdr[i].p_vaddr = 0;
                phdr[i].p_paddr = 0;
                phdr[i].p_filesz = 0;
                phdr[i].p_memsz = 0;
                phdr[i].p_flags = 0;
                phdr[i].p_align = 0;
            }
        } break;

        case PT_NOTE: {
            Elf_Scn *s = NULL;
            while ((s = elf_nextscn(out_elf, s)) != NULL) {
                GElf_Shdr sh;
                if (!gelf_getshdr(s, &sh))
                    continue;
                const char *name = elf_strptr(out_elf, shstrndx, sh.sh_name);
                if (!name)
                    continue;
                /* include any .note.* section or known note names */
                if (strncmp(name, ".note", 5) != 0 &&
                    !MATCH_NAME_IN_LIST(name, note_names))
                    continue;

                any = true;
                if (sh.sh_offset < min_off)
                    min_off = sh.sh_offset;
                if (sh.sh_offset + sh.sh_size > max_off)
                    max_off = sh.sh_offset + sh.sh_size;
                if (sh.sh_addr < min_addr)
                    min_addr = sh.sh_addr;
                if (sh.sh_addr + sh.sh_size > max_addr)
                    max_addr = sh.sh_addr + sh.sh_size;
            }

            if (any) {
                phdr[i].p_offset = min_off;
                phdr[i].p_vaddr = min_addr;
                phdr[i].p_paddr = phdr[i].p_vaddr;
                phdr[i].p_filesz = (max_off - min_off);
                phdr[i].p_memsz = (max_addr - min_addr);
                phdr[i].p_flags = PF_R;
                phdr[i].p_align = 4;
            } else {
                phdr[i].p_offset = 0;
                phdr[i].p_vaddr = 0;
                phdr[i].p_paddr = 0;
                phdr[i].p_filesz = 0;
                phdr[i].p_memsz = 0;
                phdr[i].p_flags = 0;
                phdr[i].p_align = 0;
            }
        } break;

        case PT_GNU_EH_FRAME: {
            Elf_Scn *s = NULL;
            while ((s = elf_nextscn(out_elf, s)) != NULL) {
                GElf_Shdr sh;
                if (!gelf_getshdr(s, &sh))
                    continue;
                const char *name = elf_strptr(out_elf, shstrndx, sh.sh_name);
                if (!name)
                    continue;
                if (!MATCH_NAME_IN_LIST(name, ehframe_names))
                    continue;

                any = true;
                if (sh.sh_offset < min_off)
                    min_off = sh.sh_offset;
                if (sh.sh_offset + sh.sh_size > max_off)
                    max_off = sh.sh_offset + sh.sh_size;
                if (sh.sh_addr < min_addr)
                    min_addr = sh.sh_addr;
                if (sh.sh_addr + sh.sh_size > max_addr)
                    max_addr = sh.sh_addr + sh.sh_size;
            }

            if (any) {
                phdr[i].p_offset = min_off;
                phdr[i].p_vaddr = min_addr;
                phdr[i].p_paddr = phdr[i].p_vaddr;
                phdr[i].p_filesz = (max_off - min_off);
                phdr[i].p_memsz = (max_addr - min_addr);
                phdr[i].p_flags = PF_R;
                phdr[i].p_align = 4;
            } else {
                phdr[i].p_offset = 0;
                phdr[i].p_vaddr = 0;
                phdr[i].p_paddr = 0;
                phdr[i].p_filesz = 0;
                phdr[i].p_memsz = 0;
                phdr[i].p_flags = 0;
                phdr[i].p_align = 0;
            }
        } break;

        case PT_GNU_RELRO: {
            Elf_Scn *s = NULL;
            while ((s = elf_nextscn(out_elf, s)) != NULL) {
                GElf_Shdr sh;
                if (!gelf_getshdr(s, &sh))
                    continue;
                if (!(sh.sh_flags & SHF_ALLOC))
                    continue;
                const char *name = elf_strptr(out_elf, shstrndx, sh.sh_name);
                if (!name)
                    continue;
                if (!MATCH_NAME_IN_LIST(name, relro_names))
                    continue;

                any = true;
                if (sh.sh_offset < min_off)
                    min_off = sh.sh_offset;
                if (sh.sh_offset + sh.sh_size > max_off)
                    max_off = sh.sh_offset + sh.sh_size;
                if (sh.sh_addr < min_addr)
                    min_addr = sh.sh_addr;
                if (sh.sh_addr + sh.sh_size > max_addr)
                    max_addr = sh.sh_addr + sh.sh_size;
            }

            if (any) {
                // phdr[i].p_offset = ALIGN_DOWN(min_off, PAGE_ALIGN);
                phdr[i].p_offset = min_off;
                // phdr[i].p_vaddr = ALIGN_DOWN(min_addr, PAGE_ALIGN);
                phdr[i].p_vaddr = min_addr;
                phdr[i].p_paddr = phdr[i].p_vaddr;
                phdr[i].p_filesz = max_off - phdr[i].p_offset;
                phdr[i].p_memsz = phdr[i].p_filesz;
                phdr[i].p_flags = PF_R;
                phdr[i].p_align = 0x1;
            } else {
                phdr[i].p_offset = 0;
                phdr[i].p_vaddr = 0;
                phdr[i].p_paddr = 0;
                phdr[i].p_filesz = 0;
                phdr[i].p_memsz = 0;
                phdr[i].p_flags = 0;
                phdr[i].p_align = 0;
            }
        } break;

        case PT_PHDR:
            phdr[i].p_offset = eh->e_phoff;
            phdr[i].p_vaddr = phdr[i].p_offset;
            phdr[i].p_paddr = phdr[i].p_offset;
            phdr[i].p_filesz = elf64_fsize(ELF_T_PHDR, out_phnum, EV_CURRENT);
            phdr[i].p_memsz = phdr[i].p_filesz;
            phdr[i].p_flags = PF_R;
            phdr[i].p_align = sizeof(Elf64_Addr);
            break;

        default:
            /* For other segment types (e.g. PT_TLS, PT_NOTE already handled)
               try a generic name-based inclusion: include any section that
               exactly matches the segment name set you care about - nothing by
               default. */
            { /* If you want to handle PT_TLS etc. add cases here */
            }
            break;
        } /* switch */
    }     /* for phdr */

    Elf64_Addr entry = 0;
    for (size_t i = 0; i < out_phnum; ++i) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
            entry = phdr[i].p_vaddr;
            break;
        }
    }
    Elf64_Ehdr *out_ehdr = elf64_getehdr(out_elf);
    out_ehdr->e_entry = entry;

    elf_flagphdr(out_elf, ELF_C_SET, ELF_F_DIRTY);
    return STRIPS_OK;
}

STRIPS_ERROR strips_move_sections(Elf *in_elf, Elf *out_elf,
                                  const strip_policy_t policy) {
    assert(in_elf);

    Elf64_Ehdr *in_ehdr;
    Elf64_Phdr *in_phdr;

    Elf64_Ehdr *out_ehdr;
    Elf64_Phdr *out_phdr;

    if ((in_ehdr = elf64_getehdr(in_elf)) == NULL) {
        ERROR("elf64_getehdr failed\n");
    }

    if ((out_ehdr = elf64_newehdr(out_elf)) == NULL) {
        ERROR("elf64_newehdr failed\n");
    }

    memcpy(out_ehdr->e_ident, in_ehdr->e_ident, EI_NIDENT);
    out_ehdr->e_type = in_ehdr->e_type;
    out_ehdr->e_machine = in_ehdr->e_machine;
    out_ehdr->e_version = in_ehdr->e_version;
    out_ehdr->e_entry = in_ehdr->e_entry;
    out_ehdr->e_flags = in_ehdr->e_flags;

    size_t in_phnum = 0;
    if ((elf_getphdrnum(in_elf, &in_phnum)) < 0) {
        ERROR("elf_getphdrnum failed\n");
    }

    if ((in_phdr = elf64_getphdr(in_elf)) == NULL) {
        ERROR("elf64_getphdr failed\n");
    }

    if ((out_phdr = elf64_newphdr(out_elf, in_phnum)) == NULL) {
        ERROR("elf64_newphdr failed\n");
    }

    for (size_t i = 0; i < in_phnum; ++i) {
        // out_phdr[i].p_align = in_phdr[i].p_align;
        // out_phdr[i].p_filesz = in_phdr[i].p_filesz;
        // out_phdr[i].p_flags = in_phdr[i].p_flags;
        // out_phdr[i].p_memsz = in_phdr[i].p_memsz;
        // out_phdr[i].p_offset = in_phdr[i].p_offset;
        // out_phdr[i].p_paddr = in_phdr[i].p_paddr;
        // out_phdr[i].p_type = in_phdr[i].p_type;
        // out_phdr[i].p_vaddr = in_phdr[i].p_vaddr;
        out_phdr[i] = in_phdr[i];
    }

    size_t shdrstrndx = 0;
    if (elf_getshdrstrndx(in_elf, &shdrstrndx) < 0) {
        return STRIPS_SHDR_FAILURE;
    }

    Elf_Scn *in_scn = NULL;
    while ((in_scn = elf_nextscn(in_elf, in_scn)) != NULL) {
        Elf_Scn *out_scn = elf_newscn(out_elf);

        Elf_Data *in_data = NULL;
        while ((in_data = elf_getdata(in_scn, in_data)) != NULL) {
            Elf_Data *out_data = NULL;
            if ((out_data = elf_newdata(out_scn)) != NULL) {
                out_data->d_align = in_data->d_align;
                // out_data->d_off = in_data->d_off;
                if (in_data->d_buf != NULL) {
                    out_data->d_buf = calloc(in_data->d_size, 1);
                    memcpy(out_data->d_buf, in_data->d_buf, in_data->d_size);
                }
                out_data->d_size = in_data->d_size;
                out_data->d_version = EV_CURRENT;
            }
        }

        Elf64_Shdr *in_shdr = NULL;
        if ((in_shdr = elf64_getshdr(in_scn)) == NULL) {
            ERROR("elf64_getshdr in_scn failed\n");
        }

        Elf64_Shdr *out_shdr = NULL;
        if ((out_shdr = elf64_getshdr(out_scn)) == NULL) {
            ERROR("elf64_getshdr out_scn failed\n");
        }

        out_shdr->sh_name = in_shdr->sh_name;
        out_shdr->sh_type = in_shdr->sh_type;
        out_shdr->sh_flags = in_shdr->sh_flags;
        out_shdr->sh_addr = in_shdr->sh_addr;
        out_shdr->sh_addralign = 0x8;
        out_shdr->sh_entsize = in_shdr->sh_entsize;
        out_shdr->sh_link = in_shdr->sh_link;
        out_shdr->sh_info = in_shdr->sh_info;
        out_shdr->sh_size = in_shdr->sh_size;
    }

    size_t shdrstr_idx;
    if (elf_getshdrstrndx(in_elf, &shdrstr_idx) != 0) {
        return STRIPS_SHDR_FAILURE;
    }

    out_ehdr->e_shstrndx = shdrstr_idx;

    if (elf_update(out_elf, ELF_C_NULL) < 0) {
        fprintf(stderr, "elf_update (nonfinal) failed: %s\n",
                elf_errmsg(elf_errno()));
        return STRIPS_FAILURE;
    }

    STRIPS_ERROR_HANDLE(recompute_program_headers(in_elf, out_elf));

    if (elf_update(out_elf, ELF_C_WRITE) < 0) {
        fprintf(stderr, "elf_update (final) failed: %s\n",
                elf_errmsg(elf_errno()));
        return STRIPS_FAILURE;
    }

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