#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "strips/lib_strips.h"

void print_usage() { fprintf(stderr, "usage: strips [-d] <ELF-file>\n"); }

bool manage_options(int argc, char **argv) {
    int opt = 0;

    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
        case ('d'): {
            return true;
        }
        case ('?'): {
            print_usage();
            exit(EXIT_FAILURE);
        }
        default: {
            return false;
        }
        }
    }
    return false;
}

int main(int argc, char **argv) {
    manage_options(argc, argv);
    elf_check_magic(NULL);
}