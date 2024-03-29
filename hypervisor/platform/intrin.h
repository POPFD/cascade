#ifndef INTRIN_H
#define INTRIN_H

#include <stdint.h>
#include "platform/standard.h"

extern __attribute__((ms_abi)) uint16_t __readcs();
extern __attribute__((ms_abi)) uint64_t __readcr0();
extern __attribute__((ms_abi)) uint64_t __readcr2();
extern __attribute__((ms_abi)) uint64_t __readcr3();
extern __attribute__((ms_abi)) uint64_t __readcr4();
extern __attribute__((ms_abi)) uint64_t __readdr7();
extern __attribute__((ms_abi)) uint64_t __rdtsc(void);
extern __attribute__((ms_abi)) void __writecr0(uint64_t cr0);
extern __attribute__((ms_abi)) void __writecr3(uint64_t cr3);
extern __attribute__((ms_abi)) void __writecr4(uint64_t cr4);
extern __attribute__((ms_abi)) void __lidt(void *idt);
extern __attribute__((ms_abi)) void __sidt(void *idt);
extern __attribute__((ms_abi)) void __lgdt(void *gdt);
extern __attribute__((ms_abi)) void __sgdt(void *gdt);
extern __attribute__((ms_abi)) void __lldt(void *ldt);
extern __attribute__((ms_abi)) void __sldt(void *ldt);
extern __attribute__((ms_abi)) void __str(void *tr);
extern __attribute__((ms_abi)) void __ltr(void *tr);
extern __attribute__((ms_abi)) void __xsetbv(uint64_t field, uint64_t val);
extern __attribute__((ms_abi)) void __invd(void);
extern __attribute__((ms_abi)) void __invlpg(uintptr_t *addr);
extern __attribute__((ms_abi)) void __invept(uint64_t ext, void *addr);
extern __attribute__((ms_abi)) int __vmxon(void *vmxon);
extern __attribute__((ms_abi)) int __vmclear(void *vmcs);
extern __attribute__((ms_abi)) int __vmptrld(void *vmcs);
extern __attribute__((ms_abi)) void __vmwrite(size_t field, size_t value);
extern __attribute__((ms_abi)) size_t __vmread(size_t field);
extern __attribute__((ms_abi)) int __vmlaunch(void);
extern __attribute__((ms_abi, noreturn)) void __vmresume(void);
extern __attribute__((ms_abi)) void __capture_context(void *context);
extern __attribute__((ms_abi)) void __restore_context(void *context);

#endif /* INTRIN_H */