#ifndef EPT_H
#define EPT_H

#include "ia32_compact.h"

struct ept_ctx *ept_init(void);
eptp *ept_get_pointer(struct ept_ctx *ctx);

#endif /* EPT_H */