#include "strips.h"

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

#define MAX_FILENAME_LEN 256
const size_t kDebugLineLen = 6;     // i wanted to use strlen but it fails to compile with cpp
const size_t kShstrtabLineLen = 9;  // i wanted to use strlen but it fails to compile with cpp

typedef struct {
    Elf_Scn* old_scn;
    Elf64_Word old_sh_link;
    Elf64_Word new_section_index;
    bool keep;
} SectionMapping;

static bool StripsShouldStrip(const char* name, Elf64_Shdr* sec_head, const StripPolicy k_policy) {
    bool remove = false;
    if (k_policy.debug == true && name != nullptr && strncmp(name, ".debug", kDebugLineLen) == 0) {
        return true;
    }
    if (k_policy.symtab == true && sec_head != nullptr && sec_head->sh_type == SHT_SYMTAB) {
        remove = true;
    }
    if (name != nullptr && strncmp(name, ".shstrtab", kShstrtabLineLen) == 0) {
        remove = true;
    }

    return remove;
}

static bool StripsCheckMagic(Elf* elf) {
    if (elf == nullptr) {
        return true;
    }

    GElf_Ehdr ehdr;
    if (gelf_getehdr(elf, &ehdr) == nullptr) {
        fprintf(stderr, "%s\n", elf_errmsg(elf_errno()));
        return true;
    }

    unsigned char* e_ident = ehdr.e_ident;
    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 || e_ident[EI_MAG2] != ELFMAG2 ||
        e_ident[EI_MAG3] != ELFMAG3) {
        ERROR(true, "bad elf magic", (void)(0));
    }

    if (e_ident[EI_CLASS] != ELFCLASS32 && e_ident[EI_CLASS] != ELFCLASS64) {
        ERROR(true, "bad elf class", (void)(0));
    }

    if (e_ident[EI_DATA] != ELFDATA2LSB) {
        ERROR(true, "bad endianness", (void)(0));
    }

    if (ehdr.e_ehsize < sizeof(Elf64_Ehdr)) {
        ERROR(true, "bad elf format", (void)(0));
    }

    if (ehdr.e_shnum == 0 || ehdr.e_shoff == 0) {
        ERROR(true, "bad section table", (void)(0));
    }

    if (ehdr.e_phnum == 0 || ehdr.e_phoff == 0) {
        ERROR(true, "bad program header table", (void)(0));
    }

    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        ERROR(true, "bad shstrndx", (void)(0));
    }

    return false;
}

StripsError StripsBuildNewStrtab(Elf* old_elf, Elf* new_elf, SectionMapping* sections,
                                 size_t sections_count, size_t* strtabndx, char** data);

StripsError StripsAnalyzeSections(Elf* elf, SectionMapping* sections, const StripPolicy k_policy) {
    assert(elf);

    size_t last_section = 0;

    size_t shdrstr_idx;
    if (elf_getshdrstrndx(elf, &shdrstr_idx) != 0) {
        return STRIPS_SHDR_FAILURE;
    }

    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        Elf64_Shdr* shdr = elf64_getshdr(scn);
        if (shdr == nullptr) {
            return STRIPS_SHDR_FAILURE;
        }

        sections[last_section] = {
            .old_scn = scn, .old_sh_link = shdr->sh_link, .new_section_index = 0, .keep = false};

        char* name = elf_strptr(elf, shdrstr_idx, shdr->sh_name);
        if (!StripsShouldStrip(name, shdr, k_policy)) {
            sections[last_section].keep = true;
        }

        ++last_section;
    }
    return STRIPS_OK;
}

StripsError StripsCopySegments(Elf* old_elf, Elf* new_elf) {
    assert(old_elf && new_elf);

    size_t old_phdrnum = 0;
    if (elf_getphdrnum(old_elf, &old_phdrnum) == -1) {
        perror("can't get old program header number");
        return STRIPS_EHDR_FAILURE;
    }

    Elf64_Phdr* old_phdrs = elf64_getphdr(old_elf);
    Elf64_Phdr* new_phdrs = elf64_newphdr(new_elf, old_phdrnum);

    for (size_t i = 0; i < old_phdrnum; ++i) {
        Elf64_Phdr* old_phdr = &old_phdrs[i];
        Elf64_Phdr* new_phdr = &new_phdrs[i];

        memcpy(new_phdr, old_phdr, sizeof(*old_phdr));
    }

    return STRIPS_OK;
}

StripsError StripsBuildNewStrtab(Elf* old_elf, Elf* new_elf, SectionMapping* sections,
                                 size_t sections_count, size_t* strtabndx, char** data) {
    size_t shstrtab_len = 1;
    char* shstrtab_buf = static_cast<char*>(calloc(1, sizeof(*shstrtab_buf)));
    if (shstrtab_buf == nullptr) {
        return STRIPS_FAILURE;
    }
    shstrtab_buf[0] = '\0';

    const char* selfname = ".shstrtab";
    size_t selfname_len = kShstrtabLineLen + 1;
    char* tmp = static_cast<char*>(realloc(shstrtab_buf, shstrtab_len + selfname_len));
    if (tmp == nullptr) {
        return STRIPS_FAILURE;
    }
    shstrtab_buf = tmp;
    memcpy(shstrtab_buf + shstrtab_len, selfname, selfname_len);
    shstrtab_len += selfname_len;

    size_t old_shstrndx = 0;
    if (elf_getshdrstrndx(new_elf, &old_shstrndx) != 0) {
        return STRIPS_SHDR_FAILURE;
    }

    for (size_t i = 0; i < sections_count; ++i) {
        if (sections[i].keep == false) {
            continue;
        }
        Elf64_Shdr* old_shdr = elf64_getshdr(sections[i].old_scn);
        if (old_shdr == nullptr) {
            return STRIPS_SHDR_FAILURE;
        }

        char* name = elf_strptr(old_elf, old_shstrndx, old_shdr->sh_name);
        if (name == nullptr) {
            return STRIPS_SHDR_FAILURE;
        }

        size_t name_len = strlen(name) + 1;
        char* newbuf = static_cast<char*>(realloc(shstrtab_buf, shstrtab_len + name_len));
        if (newbuf == nullptr) {
            return STRIPS_FAILURE;
        }
        shstrtab_buf = newbuf;
        memcpy(shstrtab_buf + shstrtab_len, name, name_len);

        Elf_Scn* new_section = elf_newscn(new_elf);
        if (new_section == nullptr) {
            return STRIPS_SECTION_FAILURE;
        }
        sections[i].new_section_index = elf_ndxscn(new_section);
        Elf64_Shdr* new_shdr = elf64_getshdr(new_section);
        if (new_shdr == nullptr) {
            return STRIPS_SHDR_FAILURE;
        }

        memcpy(new_shdr, old_shdr, sizeof(*old_shdr));

        new_shdr->sh_name = shstrtab_len;

        shstrtab_len += name_len;
    }

    for (size_t i = 0; i < sections_count; ++i) {
        if (sections[i].keep == false) {
            continue;
        }

        Elf_Scn* scn = elf_getscn(new_elf, sections[i].new_section_index);
        if (scn == nullptr) {
            return STRIPS_SECTION_FAILURE;
        }

        Elf64_Shdr* new_shdr = elf64_getshdr(scn);
        if (new_shdr == nullptr) {
            return STRIPS_SHDR_FAILURE;
        }

        size_t new_sh_link = SHN_UNDEF;
        if (sections[i].old_sh_link != SHN_UNDEF) {
            new_sh_link = sections[sections[i].old_sh_link - 1].new_section_index;
            if (sections[sections[i].old_sh_link - 1].keep == false) {
                new_sh_link = SHN_UNDEF;
            }
        }
        new_shdr->sh_link = new_sh_link;
    }

    Elf_Scn* shstrtab_section = nullptr;
    if ((shstrtab_section = elf_newscn(new_elf)) == nullptr) {
        return STRIPS_SHDR_FAILURE;
    }

    Elf64_Shdr* shstrtab_shdr = nullptr;
    if ((shstrtab_shdr = elf64_getshdr(shstrtab_section)) == nullptr) {
        return STRIPS_SHDR_FAILURE;
    }

    size_t old_shstrtab_offt = 0;
    {
        Elf_Scn* old_shstrtab = elf_getscn(old_elf, old_shstrndx);
        if (old_shstrtab == nullptr) {
            return STRIPS_SHDR_FAILURE;
        }

        Elf64_Shdr* shdr = elf64_getshdr(old_shstrtab);
        if (shdr == nullptr) {
            return STRIPS_SHDR_FAILURE;
        }

        old_shstrtab_offt = shdr->sh_offset;
    }
    shstrtab_shdr->sh_name = 1;
    shstrtab_shdr->sh_type = SHT_STRTAB;
    shstrtab_shdr->sh_size = shstrtab_len;
    shstrtab_shdr->sh_offset = old_shstrtab_offt;

    Elf_Data* shstrtab_data = nullptr;
    if ((shstrtab_data = elf_getdata(shstrtab_section, shstrtab_data)) == nullptr) {
        return STRIPS_SHDR_FAILURE;
    }

    /* Attach data to the new shstrtab section */
    shstrtab_data->d_buf = shstrtab_buf;
    shstrtab_data->d_size = shstrtab_len;
    shstrtab_data->d_off = 0;
    shstrtab_data->d_align = 1;
    shstrtab_data->d_version = EV_CURRENT;

    if ((*strtabndx = elf_ndxscn(shstrtab_section)) == SHN_UNDEF) {
        return STRIPS_SECTION_FAILURE;
    }

    *data = shstrtab_buf;

    return STRIPS_OK;
}

StripsError StripsRebuildFile(Elf* old_elf, Elf* new_elf, const StripPolicy k_policy, char** data) {
    assert(old_elf);

    Elf64_Ehdr* old_ehdr = elf64_getehdr(old_elf);
    if (old_ehdr == nullptr) {
        return STRIPS_EHDR_FAILURE;
    }

    Elf64_Ehdr* new_ehdr = elf64_newehdr(new_elf);
    memcpy(new_ehdr, old_ehdr, sizeof(*old_ehdr));

    SectionMapping* sections =
        static_cast<SectionMapping*>(calloc(old_ehdr->e_shnum, sizeof((*sections))));
    STRIPS_ERROR_HANDLE(StripsCopySegments(old_elf, new_elf));
    STRIPS_ERROR_HANDLE(StripsAnalyzeSections(old_elf, sections, k_policy));
    size_t new_strtabidx = 0;

    STRIPS_ERROR_HANDLE(
        StripsBuildNewStrtab(old_elf, new_elf, sections, old_ehdr->e_shnum, &new_strtabidx, data),
        free(data));

    new_ehdr->e_shstrndx = new_strtabidx;
    free(sections);
    return STRIPS_OK;
}

static bool StripsCopyFileContents(int ifd, int ofd) {
    char buf[4096];
    ssize_t n;

    if (lseek(ifd, 0, SEEK_SET) == -1 || lseek(ofd, 0, SEEK_SET) == -1) {
        perror("lseek failed");
        return false;
    }

    while ((n = read(ifd, buf, sizeof(buf))) > 0) {
        if (write(ofd, buf, n) != n) {
            perror("write failed");
            return false;
        }
    }

    if (n < 0) {
        perror("read failed");
        return false;
    }

    return true;
}

StripsError StripsProcessFile(const char* filename, const StripPolicy k_policy) {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        ERROR(STRIPS_FAILURE, "ELF library version mismatch", (void)(0));
    }

    int ifd = open(filename, O_RDONLY);
    if (ifd < 0) {
        perror("Can't open input file decriptor");
        ERROR(STRIPS_FAILURE, "open failed", (void)(0));
    }

    Elf* in_elf = elf_begin(ifd, ELF_C_READ, nullptr);
    if (in_elf == nullptr) {
        perror(elf_errmsg(elf_errno()));
        ERROR(STRIPS_FAILURE, "elf_begin failed", close(ifd));
    }

    if (StripsCheckMagic(in_elf)) {
        ERROR(STRIPS_FAILURE, "bad elf file", elf_end(in_elf), close(ifd));
    }

    char stripped_filename[MAX_FILENAME_LEN];
    snprintf(stripped_filename, MAX_FILENAME_LEN, "%s.stripped", filename);
    int ofd = open(stripped_filename, O_RDWR | O_CREAT | O_TRUNC, 0777);

    if (ofd < 0) {
        perror("Can't open output file decriptor");
        ERROR(STRIPS_FAILURE, "open failed", elf_end(in_elf), close(ifd));
    }

    if (StripsCopyFileContents(ifd, ofd) == false) {
        return STRIPS_FAILURE;
    }

    Elf* out_elf = elf_begin(ofd, ELF_C_WRITE, nullptr);
    if (out_elf == nullptr) {
        perror(elf_errmsg(elf_errno()));
        ERROR(STRIPS_FAILURE, "elf_begin failed", elf_end(in_elf), close(ifd), close(ofd));
    }

    // TODO: mark output elf file with this
    if (elf_flagelf(out_elf, ELF_C_SET, ELF_F_LAYOUT) == 0) {
        fprintf(stderr, "Failed to set LAYOUT flag for ELF file: %s\n", elf_errmsg(-1));
        return STRIPS_FAILURE;
    }
    char* data = nullptr;
    STRIPS_ERROR_HANDLE(StripsRebuildFile(in_elf, out_elf, k_policy, &data), (void)(0));

    if (elf_update(out_elf, ELF_C_WRITE) == -1) {
        fprintf(stderr, "%s\n", (elf_errmsg(-1)));
        ERROR(STRIPS_FAILURE, "elf_update failed", elf_end(in_elf), close(ifd));
    }

    free(data);

    elf_end(in_elf);
    close(ifd);
    elf_end(out_elf);

    rename(stripped_filename, filename);

    close(ofd);
    return STRIPS_OK;
}

#define CASE_ENUM_TO_STRING_(error) \
    case error:                     \
        return #error

const char* StripsStrerror(const StripsError k_error) {
    switch (k_error) {
        CASE_ENUM_TO_STRING_(STRIPS_OK);
        CASE_ENUM_TO_STRING_(STRIPS_FAILURE);
        CASE_ENUM_TO_STRING_(STRIPS_EHDR_FAILURE);
        CASE_ENUM_TO_STRING_(STRIPS_SHDR_FAILURE);
        CASE_ENUM_TO_STRING_(STRIPS_PHNUM_FAILURE);
        CASE_ENUM_TO_STRING_(STRIPS_PHDR_FAILURE);
        CASE_ENUM_TO_STRING_(STRIPS_SECTION_FAILURE);
        default:
            return "UNKNOWN_STRIPS_ERROR";
    }
    return "UNKNOWN_STRIPS_ERROR";
}

#undef CASE_ENUM_TO_STRING_
