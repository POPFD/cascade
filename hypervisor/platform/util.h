#ifndef UTIL_H
#define UTIL_H

#include "standard.h"

static inline void bitmap_clear_bit(uint8_t *bitmap, size_t bit)
{
    size_t idx = bit / 8;
    size_t pos = bit % 8;

    bitmap[idx] &= ~(1 << pos);
}

static inline void bitmap_set_bit(uint8_t *bitmap, size_t bit)
{
    size_t idx = bit / 8;
    size_t pos = bit % 8;

    bitmap[idx] |= 1 << pos;
}

#endif /* UTIL_H */