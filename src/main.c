#include <fcntl.h>
#include <gelf.h>
#include <getopt.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "strips/lib_strips.h"
#include "strips/src/strips.h"

void print_usage() { fprintf(stderr, "usage: strips [-d] <ELF-file>\n"); }

bool manage_options(int argc, char **argv, char **filename) {
    int opt = 0;
    bool debug_mode = false;

    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
        case ('d'): {
            debug_mode = true;
        }
        case ('?'): {
            print_usage();
            exit(EXIT_FAILURE);
        }
        default: {
            debug_mode = false;
        }
        }
    }

    // Get the filename from non-option arguments
    if (optind >= argc) {
        fprintf(stderr, "Error: ELF filename is required\n");
        print_usage();
        exit(EXIT_FAILURE);
    }

    *filename = argv[optind];
    return debug_mode;
}

int main(int argc, char **argv) {
    char *filename = NULL;
    manage_options(argc, argv, &filename);

    if (filename == NULL) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "%s\n", filename);

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "can't open desired file\n");
        exit(EXIT_FAILURE);
    }

    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    if (!e) {
        ERROR("elf_begin failed\n", close(fd));
    }

    GElf_Ehdr ehdr;
    if (gelf_getehdr(e, &ehdr) == NULL) {
        ERROR("getehdr failed\n", close(fd));
    }

    printf("ELF entry point 0x%jx\n", (uintmax_t)ehdr.e_entry);

    close(fd);
}