#ifndef INTRIN_H
#define INTRIN_H

#include <stdint.h>

extern __attribute__((ms_abi)) uint16_t __readcs();
extern __attribute__((ms_abi)) uint64_t __readcr3();
extern __attribute__((ms_abi)) void __writecr3(uint64_t cr3);

#endif /* INTRIN_H */