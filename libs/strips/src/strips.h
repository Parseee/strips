#pragma once

#include <elf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define STRIPS_ERROR_HANDLE(call_func, ...)                                    \
    do {                                                                       \
        STRIPS_ERROR error_handler = call_func;                                \
        if (error_handler) {                                                   \
            fprintf(stderr,                                                    \
                    "Error calling " #call_func " on line %d,"                 \
                    " file %s. error is %s\n",                                 \
                    __LINE__, __FILE__, strips_strerror(error_handler));       \
            __VA_ARGS__;                                                       \
            return error_handler;                                              \
        }                                                                      \
    } while (0)

#define ERROR(err_msg)                                                         \
    do {                                                                       \
        fprintf(stderr, err_msg "\n");                                         \
        exit(EXIT_FAILURE);                                                    \
    } while (0)

typedef enum { STRIPS_OK, STRIPS_FAILURE } STRIPS_ERROR;

bool elf_check_magic(Elf32_Ehdr *hdr);