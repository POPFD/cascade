#ifndef STANDARD_H
#define STANDARD_H

#include <efi.h>
#include <efilib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "arch.h"
#include "intrin.h"

/* Size definitions */
#define GiB(x) ((size_t)(x) << 30)
#define MiB(x) ((size_t)(x) << 20)
#define KiB(x) ((size_t)(x) << 10)

/* Architecture definitions. */
#define PAGE_SIZE 0x1000
#define PAGE_MASK (PAGE_SIZE - 1)

#define ADDRMASK_PML4_INDEX(addr)   (((size_t)addr & 0xFF8000000000ULL) >> 39)
#define ADDRMASK_PDPTE_INDEX(addr)  (((size_t)addr & 0x7FC0000000ULL) >> 30)
#define ADDRMASK_PDE_INDEX(addr)    (((size_t)addr & 0x3FE00000ULL) >> 21)
#define ADDRMASK_PTE_INDEX(addr)    (((size_t)addr & 0x1FF000ULL) >> 12)

#define ADDRMASK_PDPTE_OFFSET(_VAR_)    ((size_t)_VAR_ & 0x3FFFFFFFULL)
#define ADDRMASK_PDE_OFFSET(_VAR_)      ((size_t)_VAR_ & 0x1FFFFFULL)
#define ADDRMASK_PTE_OFFSET(addr)       ((size_t)addr & 0xFFFULL)

/* Utility macros */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define NUMBER_BITS_TYPE(type) (sizeof(type) * 8)

/* Debug printing */
static inline void print_format(char *file, const char *func, int line, const CHAR16 *format, ...)
{
    va_list marker;

    uint64_t tsc = rdmsr(0x00000010);

    va_start(marker, format);
    APrint((const CHAR8 *)"[0x%lX] %a %a (L%04d) - ", tsc, file, func, line);
    VPrint((const CHAR16 *)format, marker);
    va_end(marker);
}

#define debug_print(format, ...) print_format(__FILE__, __func__, __LINE__, format, ##__VA_ARGS__)

#define die_on(cond, ...) do { \
        if (cond) { \
            debug_print(__VA_ARGS__); \
            while (1) {} \
        } \
    } while (0)

#define assert(cond) die_on(!(cond), L"assertion failed.\n");

#endif /* STANDARD_H */