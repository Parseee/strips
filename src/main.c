#include <elf.h>
#include <getopt.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdio.h>

#include "strips/lib_strips.h"
#include "strips/src/strips.h"

void print_usage() { fprintf(stderr, "usage: strips [-d] <ELF-file>\n"); }

strip_policy_t manage_options(int argc, char **argv, char **filename) {
    int opt = 0;
    strip_policy_t policy = {};

    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
        case ('d'): {
            policy.symtab = true;
        }
        case ('?'): {
            print_usage();
            exit(EXIT_FAILURE);
        }
        default: {
            policy.symtab = false;
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
    return policy;
}

int main(int argc, char **argv) {
    char *filename = NULL;
    strip_policy_t policy = manage_options(argc, argv, &filename);

    if (filename == NULL) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    strips_process_file(filename, policy);
}