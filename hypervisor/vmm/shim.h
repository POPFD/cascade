#ifndef SHIM_H
#define SHIM_H

#include <stdint.h>

extern __attribute__((ms_abi)) void shim_guest_to_host(void);
extern __attribute__((ms_abi)) void shim_host_to_guest(void);

#endif /* SHIM_H */