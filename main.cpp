#include "src/strips.h"

#include <elf.h>
#include <getopt.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdio.h>

void PrintUsage() {
    fprintf(stderr, "usage: strips [-d] <ELF-file>\n");
}

StripPolicy ManageOptions(int argc, char** argv, char** filename) {
    int opt = 0;
    StripPolicy policy = {.symtab = true, .debug = true};

    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
            case ('d'): {
                policy.symtab = false;
                break;
            }
            case ('?'): {
                PrintUsage();
                exit(EXIT_FAILURE);
            }
            default: {
                break;
            }
        }
    }

    // Get the filename from non-option arguments
    if (optind >= argc) {
        fprintf(stderr, "Error: ELF filename is required\n");
        PrintUsage();
        exit(EXIT_FAILURE);
    }

    *filename = argv[optind];
    return policy;
}

int main(int argc, char** argv) {
    char* filename = nullptr;
    StripPolicy policy = ManageOptions(argc, argv, &filename);

    if (filename == nullptr) {
        PrintUsage();
        exit(EXIT_FAILURE);
    }

    StripsProcessFile(filename, policy);

    return 0;
}
