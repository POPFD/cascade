#ifndef ARCH_H
#define ARCH_H

#include <stdint.h>
#include <cpuid.h>

/* CPUID ease of use. */
struct cpuid_leaf_output {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

/* This has been created so that the ia_32_compact.h defines for CPUID leafs can be used
 * without having to manually reconstruct each of the variables one by one. */
#define CPUID_LEAF_READ(leaf, output) __get_cpuid(leaf, &output.eax.flags, &output.ebx.flags, \
                                                   &output.ecx.flags, &output.edx.flags)

/* MSR and IO port handling helpers. */
static inline uint64_t rdmsr(uint64_t msr)
{
	uint32_t low, high;
	asm volatile (
		"rdmsr"
		: "=a"(low), "=d"(high)
		: "c"(msr)
	);
	return ((uint64_t)high << 32) | low;
}

static inline void wrmsr(uint64_t msr, uint64_t value)
{
	uint32_t low = value & 0xFFFFFFFF;
	uint32_t high = value >> 32;
	asm volatile (
		"wrmsr"
		:
		: "c"(msr), "a"(low), "d"(high)
	);
}

static inline void outb(uint16_t port, uint8_t val)
{
    asm volatile ( "outb %0, %1" : : "a"(val), "Nd"(port) );
}

static inline uint8_t inb(uint16_t port)
{
    uint8_t ret;
    asm volatile ( "inb %1, %0"
                   : "=a"(ret)
                   : "Nd"(port) );
    return ret;
}

/* Architecture specific register defines. */
#define CR4_VMXE_SHIFT 13ull
#define CR4_VMXE_MASK (1ull << CR4_VMXE_SHIFT)

#endif /* ARCH_H */