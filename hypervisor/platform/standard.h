#ifndef STANDARD_H
#define STANDARD_H

#include <efi.h>
#include <efilib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "printf/printf.h"
#include "arch.h"
#include "serial.h"
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
static inline void print_buffer(const char *format, ...)
{
    va_list marker;
    char tmp_buff[512] = { 0 };

    va_start(marker, format);
    vsnprintf(tmp_buff, sizeof(tmp_buff), format, marker);
    va_end(marker);
    serial_print(tmp_buff);
}

#define debug_print(format, ...) \
    do { \
        print_buffer("[0x%lX] %s %s (L%04d) - ", rdmsr(0x00000010), __FILE__, __func__, __LINE__); \
        print_buffer(format, ##__VA_ARGS__); \
        print_buffer("\r\n"); \
    } while (0)

#define die_on(cond, ...) do { \
        if (cond) { \
            debug_print(__VA_ARGS__); \
            while (1) {} \
        } \
    } while (0)

#define assert(cond) die_on(!(cond), "assertion failed.");

#ifdef DEBUG_MODULE
    #define DEBUG_PRINT(...) debug_print(__VA_ARGS__)
#else
    #define DEBUG_PRINT(...)
#endif


#endif /* STANDARD_H */