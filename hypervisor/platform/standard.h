#ifndef STANDARD_H
#define STANDARD_H

#include <efi.h>
#include <efilib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Size definitions */
#define MiB(x) ((size_t)(x) << 20)
#define KiB(x) ((size_t)(x) << 10)

/* Architecture definitions. */
#define PAGE_SIZE 0x1000

/* Utility macros */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define NUMBER_BITS_TYPE(type) (sizeof(type) * 8)

static inline void print_format(char *file, const char *func, int line, const CHAR16 *format, ...)
{
    va_list marker;

    va_start(marker, format);
    APrint((const CHAR8 *)"%a %a (L%04d) - ", file, func, line);
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