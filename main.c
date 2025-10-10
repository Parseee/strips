/*
 * recompute_segments.c
 *
 * Rebuild ELF PT_LOAD segments from section headers by hand.
 * Each group of contiguous SHF_ALLOC sections with the same
 * RWX attributes forms one segment.
 *
 * Build:
 *   cc -o recompute_segments recompute_segments.c -lelf
 *
 * Usage:
 *   ./recompute_segments input_elf output_elf
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <libelf.h>
#include <gelf.h>
#include <sysexits.h>

#define PAGE_ALIGN 0x1000ULL
#define ALIGN_DOWN(x, a) ((x) & ~((a)-1))
#define ALIGN_UP(x, a) (((x) + ((a)-1)) & ~((a)-1))

typedef struct {
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint32_t p_flags;
    uint64_t p_align;
} seg_info_t;

int main(int argc, char **argv) {
    if (argc != 3)
        errx(EX_USAGE, "usage: %s <input-elf> <output-elf>", argv[0]);

    if (elf_version(EV_CURRENT) == EV_NONE)
        errx(EX_SOFTWARE, "ELF library initialization failed: %s", elf_errmsg(-1));

    const char *infile = argv[1];
    const char *outfile = argv[2];

    int fd_in = open(infile, O_RDONLY);
    if (fd_in < 0)
        err(EX_NOINPUT, "open %s failed", infile);

    int fd_out = open(outfile, O_RDWR | O_CREAT | O_TRUNC, 0755);
    if (fd_out < 0)
        err(EX_CANTCREAT, "open %s failed", outfile);

    Elf *e_in = elf_begin(fd_in, ELF_C_READ, NULL);
    if (!e_in)
        errx(EX_SOFTWARE, "elf_begin(in) failed: %s", elf_errmsg(-1));

    if (elf_kind(e_in) != ELF_K_ELF)
        errx(EX_DATAERR, "%s is not an ELF object", infile);

    Elf *e_out = elf_begin(fd_out, ELF_C_WRITE, NULL);
    if (!e_out)
        errx(EX_SOFTWARE, "elf_begin(out) failed: %s", elf_errmsg(-1));

    /* Copy ELF header */
    GElf_Ehdr ehdr;
    if (gelf_getehdr(e_in, &ehdr) == NULL)
        errx(EX_SOFTWARE, "gelf_getehdr failed: %s", elf_errmsg(-1));
    if (gelf_newehdr(e_out, gelf_getclass(e_in)) == NULL)
        errx(EX_SOFTWARE, "gelf_newehdr failed: %s", elf_errmsg(-1));
    if (gelf_update_ehdr(e_out, &ehdr) == 0)
        errx(EX_SOFTWARE, "gelf_update_ehdr failed: %s", elf_errmsg(-1));

    /* Collect SHF_ALLOC sections */
    size_t shstrndx;
    if (elf_getshdrstrndx(e_in, &shstrndx) != 0)
        errx(EX_SOFTWARE, "elf_getshdrstrndx failed: %s", elf_errmsg(-1));

    typedef struct {
        char name[64];
        uint64_t addr, off, size, align;
        uint64_t flags;
        int exec, write;
    } section_info_t;

    section_info_t *secs = NULL;
    size_t sec_count = 0;

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(e_in, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) == NULL)
            errx(EX_SOFTWARE, "gelf_getshdr failed: %s", elf_errmsg(-1));

        if (!(shdr.sh_flags & SHF_ALLOC))
            continue;

        const char *name = elf_strptr(e_in, shstrndx, shdr.sh_name);
        if (!name) name = "<unnamed>";

        secs = realloc(secs, sizeof(section_info_t) * (sec_count + 1));
        section_info_t *s = &secs[sec_count++];
        strncpy(s->name, name, sizeof(s->name) - 1);
        s->addr = shdr.sh_addr;
        s->off  = shdr.sh_offset;
        s->size = shdr.sh_size;
        s->align = shdr.sh_addralign ? shdr.sh_addralign : 1;
        s->flags = shdr.sh_flags;
        s->exec  = !!(shdr.sh_flags & SHF_EXECINSTR);
        s->write = !!(shdr.sh_flags & SHF_WRITE);
    }

    if (sec_count == 0)
        errx(EX_DATAERR, "no SHF_ALLOC sections found");

    /* Sort sections by address */
    for (size_t i = 0; i < sec_count - 1; i++) {
        for (size_t j = i + 1; j < sec_count; j++) {
            if (secs[i].addr > secs[j].addr) {
                section_info_t tmp = secs[i];
                secs[i] = secs[j];
                secs[j] = tmp;
            }
        }
    }

    /* Build segments */
    seg_info_t *segs = NULL;
    size_t seg_count = 0;

    seg_info_t cur = {0};
    int have_cur = 0;

    for (size_t i = 0; i < sec_count; i++) {
        section_info_t *s = &secs[i];

        uint32_t sec_flags = PF_R;
        if (s->write) sec_flags |= PF_W;
        if (s->exec)  sec_flags |= PF_X;

        if (!have_cur) {
            have_cur = 1;
            cur.p_offset = ALIGN_DOWN(s->off, PAGE_ALIGN);
            cur.p_vaddr  = ALIGN_DOWN(s->addr, PAGE_ALIGN);
            cur.p_filesz = s->off + s->size - cur.p_offset;
            cur.p_memsz  = s->addr + s->size - cur.p_vaddr;
            cur.p_flags  = sec_flags;
            cur.p_align  = PAGE_ALIGN;
        } else {
            /* Same flags and contiguous (within a page)? Merge. */
            if (cur.p_flags == sec_flags &&
                s->off <= cur.p_offset + cur.p_filesz + PAGE_ALIGN) {
                uint64_t end_off = s->off + s->size;
                uint64_t end_addr = s->addr + s->size;
                if (end_off - cur.p_offset > cur.p_filesz)
                    cur.p_filesz = end_off - cur.p_offset;
                if (end_addr - cur.p_vaddr > cur.p_memsz)
                    cur.p_memsz = end_addr - cur.p_vaddr;
            } else {
                /* Push previous segment */
                segs = realloc(segs, sizeof(seg_info_t) * (seg_count + 1));
                segs[seg_count++] = cur;

                /* Start new segment */
                cur.p_offset = ALIGN_DOWN(s->off, PAGE_ALIGN);
                cur.p_vaddr  = ALIGN_DOWN(s->addr, PAGE_ALIGN);
                cur.p_filesz = s->off + s->size - cur.p_offset;
                cur.p_memsz  = s->addr + s->size - cur.p_vaddr;
                cur.p_flags  = sec_flags;
                cur.p_align  = PAGE_ALIGN;
            }
        }
    }
    if (have_cur) {
        segs = realloc(segs, sizeof(seg_info_t) * (seg_count + 1));
        segs[seg_count++] = cur;
    }

    printf("Computed %zu PT_LOAD segments\n", seg_count);
    for (size_t i = 0; i < seg_count; i++) {
        printf("Segment %zu: off=0x%08lx vaddr=0x%08lx "
               "filesz=0x%lx memsz=0x%lx flags=%c%c%c\n",
               i,
               (unsigned long)segs[i].p_offset,
               (unsigned long)segs[i].p_vaddr,
               (unsigned long)segs[i].p_filesz,
               (unsigned long)segs[i].p_memsz,
               (segs[i].p_flags & PF_R) ? 'R' : '-',
               (segs[i].p_flags & PF_W) ? 'W' : '-',
               (segs[i].p_flags & PF_X) ? 'E' : '-');
    }

    /* Write new program headers */
    if (gelf_newphdr(e_out, seg_count) == NULL)
        errx(EX_SOFTWARE, "gelf_newphdr failed: %s", elf_errmsg(-1));

    for (size_t i = 0; i < seg_count; i++) {
        GElf_Phdr ph;
        memset(&ph, 0, sizeof(ph));
        ph.p_type   = PT_LOAD;
        ph.p_offset = segs[i].p_offset;
        ph.p_vaddr  = segs[i].p_vaddr;
        ph.p_paddr  = segs[i].p_vaddr;
        ph.p_filesz = segs[i].p_filesz;
        ph.p_memsz  = segs[i].p_memsz;
        ph.p_flags  = segs[i].p_flags;
        ph.p_align  = segs[i].p_align;

        if (gelf_update_phdr(e_out, i, &ph) == 0)
            errx(EX_SOFTWARE, "gelf_update_phdr failed: %s", elf_errmsg(-1));
    }

    /* Copy all section data verbatim */
    scn = NULL;
    while ((scn = elf_nextscn(e_in, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) == NULL)
            errx(EX_SOFTWARE, "gelf_getshdr failed: %s", elf_errmsg(-1));

        Elf_Scn *new_scn = elf_newscn(e_out);
        if (!new_scn)
            errx(EX_SOFTWARE, "elf_newscn failed: %s", elf_errmsg(-1));
        if (gelf_update_shdr(new_scn, &shdr) == 0)
            errx(EX_SOFTWARE, "gelf_update_shdr failed: %s", elf_errmsg(-1));

        Elf_Data *data_in = NULL;
        while ((data_in = elf_getdata(scn, data_in)) != NULL) {
            Elf_Data *data_out = elf_newdata(new_scn);
            if (!data_out)
                errx(EX_SOFTWARE, "elf_newdata failed: %s", elf_errmsg(-1));
            memcpy(data_out, data_in, sizeof(Elf_Data));
        }
    }

    if (elf_update(e_out, ELF_C_WRITE) < 0)
        errx(EX_SOFTWARE, "elf_update failed: %s", elf_errmsg(-1));

    printf("Recomputed program headers written to %s\n", outfile);

    free(secs);
    free(segs);
    elf_end(e_in);
    elf_end(e_out);
    close(fd_in);
    close(fd_out);
    return 0;
}
