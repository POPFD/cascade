#ifndef PLUGIN_SHIM_H
#define PLUGIN_SHIM_H

/*
 * Plugin shim module to deal with differing ABI's between hypervisor (Linux GCC)
 * and DLL interface (MS_ABI).
 * 
 * I was really stupid mixing different toolchains and such therefore I have to
 * deal with it this way. I SHOULD change this in the future so that a shared
 * ABI is used both for the hypervisor and plugins.
 *
 * That way I can get rid of A LOT of the ms_abi f***ery.
 */

#include "plugin_if.h"
#include "platform/standard.h"

static void MS_ABI shim_print(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    debug_print(format, args);
    va_end(args);
}

static const struct plugin_if PLUGIN_INTERFACE = {
    .version = PLUGIN_IF_VERSION,
    .debug.print = shim_print
};


#endif /* PLUGIN_SHIM_H */