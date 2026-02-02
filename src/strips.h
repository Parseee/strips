#pragma once

#include <elf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define STRIPS_ERROR_HANDLE(call_func, ...)                             \
    do {                                                                \
        StripsError error_handler = call_func;                          \
        if (error_handler) {                                            \
            fprintf(stderr,                                             \
                    "Error calling " #call_func                         \
                    " on line %d,"                                      \
                    " file %s. error is %s\n",                          \
                    __LINE__, __FILE__, StripsStrerror(error_handler)); \
            __VA_ARGS__;                                                \
            return error_handler;                                       \
        }                                                               \
    } while (0)

#define ERROR(failcode, msg, ...) \
    do {                          \
        fprintf(stderr, msg);     \
        putchar('\n');            \
        __VA_ARGS__;              \
        return failcode;          \
    } while (0)

typedef enum {
    STRIPS_OK,
    STRIPS_FAILURE,
    STRIPS_EHDR_FAILURE,
    STRIPS_SHDR_FAILURE,
    STRIPS_PHNUM_FAILURE,
    STRIPS_PHDR_FAILURE,
    STRIPS_SECTION_FAILURE
} StripsError;

typedef struct {
    bool symtab;
    bool debug;
} StripPolicy;

StripsError StripsProcessFile(const char* filename, const StripPolicy k_policy);

const char* StripsStrerror(StripsError error);
