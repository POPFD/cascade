#ifndef INTRIN_H
#define INTRIN_H

#include <stdint.h>

extern __attribute__((ms_abi)) uint16_t __readcs();
extern __attribute__((ms_abi)) uint64_t __readcr0();
extern __attribute__((ms_abi)) uint64_t __readcr3();
extern __attribute__((ms_abi)) uint64_t __readcr4();
extern __attribute__((ms_abi)) uint64_t __readdr7();
extern __attribute__((ms_abi)) void __writecr3(uint64_t cr3);
extern __attribute__((ms_abi)) void __lidt(void *idt);
extern __attribute__((ms_abi)) void __sidt(void *idt);
extern __attribute__((ms_abi)) void __lgdt(void *gdt);
extern __attribute__((ms_abi)) void __sgdt(void *gdt);
extern __attribute__((ms_abi)) void __lldt(void *ldt);
extern __attribute__((ms_abi)) void __sldt(void *ldt);
extern __attribute__((ms_abi)) void __str(void *tr);

#endif /* INTRIN_H */