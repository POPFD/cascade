#ifndef SPINLOCK_H
#define SPINLOCK_H

#include <stdint.h>

typedef int spinlock_t;

static inline void spin_init(spinlock_t *lock)
{
    *lock = 0;
}

static inline void spin_lock(spinlock_t *lock)
{
    while (1) {
        int zero = 0;
        int one = 1;
        if (__atomic_compare_exchange(lock, &zero, &one, 0,
                                      __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            return;
    }
}

static inline void spin_unlock(spinlock_t *lock)
{
    int zero = 0;
    __atomic_store(lock, &zero, __ATOMIC_SEQ_CST);
}

#endif /* SPINLOCK_H */