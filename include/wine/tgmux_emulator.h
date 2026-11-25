#ifndef __WINE_TGMUX_EMULATOR_H
#define __WINE_TGMUX_EMULATOR_H

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Both the client and server must use the same initial address space cap. */
#define WINE_EMULATOR_DEFAULT_LIMIT 0x7fffff0000ULL

/* Parse a 64K-aligned limit leaving room for the shared user data pages.
 * The caller must clamp it to its own address space and host limits. */
static inline unsigned long long wine_emulator_limit( unsigned long long default_limit, int *valid )
{
    const char *env = getenv( "WINE_EMULATOR_LIMIT" );
    unsigned long long value;
    char *end;

    if (valid) *valid = 0;
    if (!env || !*env) return default_limit;
    errno = 0;
    value = strtoull( env, &end, 0 );
    if (*env >= '0' && *env <= '9' && !errno && !*end && value <= ~(uintptr_t)0 &&
        value >= 0x7fff0000ULL && !(value & 0xffff))
    {
        if (valid) *valid = 1;
        return value;
    }
    return default_limit;
}

/* Detect x86 emulators sharing their host's address space.
 * WINE_EMULATOR=<name> forces compatibility on; WINE_EMULATOR=0 forces it off. */
static inline int wine_emulator_detected(void)
{
    static int cached = -1;
    const char *env;

    if (cached >= 0) return cached;
    cached = 0;

    if ((env = getenv( "WINE_EMULATOR" )) && *env)
    {
        cached = (env[0] == '0' && !env[1]) ? 0 : 1;
        return cached;
    }

    if (getenv( "BOX64_VERSION" ) || getenv( "BOX64_LD_LIBRARY_PATH" ) || getenv( "BOX64_LOG" ) ||
        getenv( "BOX86_VERSION" ) || getenv( "BOX86_LD_LIBRARY_PATH" ) ||
        getenv( "FEX_TSOENABLED" ) || getenv( "FEX_ROOTFS" ) || getenv( "FEX_APP_CONFIG" ) ||
        getenv( "QEMU_LD_PREFIX" ) || getenv( "QEMU_CPU" ))
        cached = 1;

#if defined(__linux__) && defined(__x86_64__)
    if (!cached)
    {
        unsigned int regs[4], leaf;
        char brand[49];

        /* Box64 virtualizes /proc/self/exe as the guest executable, but
         * identifies itself in the CPUID brand string without any BOX64_*
         * environment variables. CPUID is always available on x86-64. */
        __asm__( "cpuid" : "=a" (regs[0]), "=b" (regs[1]), "=c" (regs[2]), "=d" (regs[3])
                 : "a" (0x80000000), "c" (0) );
        if (regs[0] >= 0x80000004)
        {
            for (leaf = 0; leaf < 3; leaf++)
            {
                __asm__( "cpuid" : "=a" (regs[0]), "=b" (regs[1]), "=c" (regs[2]), "=d" (regs[3])
                         : "a" (0x80000002 + leaf), "c" (0) );
                memcpy( brand + leaf * sizeof(regs), regs, sizeof(regs) );
            }
            brand[48] = 0;
            if (strstr( brand, "Box64" ) || strstr( brand, "box64" )) cached = 1;
        }
    }
#endif
#ifdef __linux__
    if (!cached)
    {
        /* Fallback for emulators which expose their host executable here. */
        char buf[256];
        ssize_t len = readlink( "/proc/self/exe", buf, sizeof(buf) - 1 );

        if (len > 0)
        {
            buf[len] = 0;
            if (strstr( buf, "box64" ) || strstr( buf, "box86" ) ||
                strstr( buf, "FEXInterpreter" ) || strstr( buf, "qemu-" ))
                cached = 1;
        }
    }
#endif
    return cached;
}

#endif /* __WINE_TGMUX_EMULATOR_H */
