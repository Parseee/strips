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

#define ERROR(msg, ...)                                                        \
    do {                                                                       \
        fprintf(stderr, msg);                                                  \
        __VA_ARGS__;                                                           \
        return STRIPS_FAILURE;                                                 \
    } while (0)

typedef enum {
    STRIPS_OK,
    STRIPS_FAILURE,
    STRIPS_EHDR_FAILURE,
    STRIPS_SHDR_FAILURE,
    STRIPS_PHNUM_FAILURE,
    STRIPS_PHDR_FAILURE
} STRIPS_ERROR;

typedef struct {
    bool symtab;
    bool debug;
} strip_policy_t;

bool strips_check_magic(Elf32_Ehdr *hdr);

STRIPS_ERROR strips_process_file(const char *filename,
                                 const strip_policy_t policy);

const char *strips_strerror(const STRIPS_ERROR error);