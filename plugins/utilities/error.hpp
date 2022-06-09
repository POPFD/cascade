#ifndef ERROR_H
#define ERROR_H

#include <stdio.h>

#define user_die_on(cond, ...) do { \
        if (cond) { \
            printf(__VA_ARGS__); \
            while (1) {} \
        } \
    } while (0)

#endif /* ERROR_H */