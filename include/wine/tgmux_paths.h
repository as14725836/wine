/*
 * Wine for Termux glibc
 *
 * Centralised host path policy for a private Termux-glibc prefix.
 *
 * Wine normally takes its host paths from FHS defaults (/usr, /etc, /tmp).
 * On Termux those locations either do not exist or are the Bionic rootfs,
 * while the whole glibc toolchain lives in a private prefix such as
 * /data/data/com.termux/files/usr/glibc. Route every such path through this
 * header so the prefix can be changed at build time or overridden per run.
 *
 * Resolution order, highest priority first:
 *   1. environment variable (runtime override)
 *   2. value baked in from WINE_TGMUX_PREFIX
 *
 * WINE_TGMUX_PREFIX can be overridden at configure time, e.g.
 *   CPPFLAGS='-DWINE_TGMUX_PREFIX="/data/data/com.termux/files/usr/glibc"'
 */

#ifndef __WINE_TGMUX_PATHS_H
#define __WINE_TGMUX_PATHS_H

#ifndef __WINE_CONFIG_H
#error This header must be included after config.h
#endif

#include <stdlib.h>

#ifndef WINE_TGMUX_PREFIX
#define WINE_TGMUX_PREFIX "/data/data/com.termux/files/usr/glibc"
#endif

/* Compile-time concatenation of a literal suffix onto the prefix. */
#define WINE_TGMUX_PATH( suffix ) WINE_TGMUX_PREFIX suffix

/* Return `name` from the environment when set and non-empty, else `fallback`. */
static inline const char *tgmux_env( const char *name, const char *fallback )
{
    const char *value = getenv( name );
    return (value && *value) ? value : fallback;
}

/* $WINE_TMP_DIR, then $TMPDIR, then <prefix>/tmp. */
static inline const char *tgmux_tmpdir(void)
{
    const char *value = getenv( "WINE_TMP_DIR" );
    if (value && *value) return value;
    value = getenv( "TMPDIR" );
    if (value && *value) return value;
    return WINE_TGMUX_PATH( "/tmp" );
}

static inline const char *tgmux_sysconfdir(void)
{
    return tgmux_env( "WINE_SYSCONF_DIR", WINE_TGMUX_PATH( "/etc" ) );
}

static inline const char *tgmux_datadir(void)
{
    return tgmux_env( "WINE_DATA_DIR", WINE_TGMUX_PATH( "/share" ) );
}

static inline const char *tgmux_localstatedir(void)
{
    return tgmux_env( "WINE_LOCALSTATE_DIR", WINE_TGMUX_PATH( "/var" ) );
}

static inline const char *tgmux_zonedir(void)
{
    return tgmux_env( "WINE_TZDIR", WINE_TGMUX_PATH( "/share/zoneinfo" ) );
}

/*
 * Root exported as the Z: drive. Exposing the whole host root inside a
 * Windows prefix is not desirable on Android, so keep it inside the
 * Termux private tree by default.
 */
static inline const char *tgmux_zdrive_root(void)
{
    return tgmux_env( "WINE_ZDRIVE_ROOT", "/data/data/com.termux/files" );
}

#endif /* __WINE_TGMUX_PATHS_H */
