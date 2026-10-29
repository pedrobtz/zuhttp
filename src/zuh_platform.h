/* zuhttp — portability layer.
 *
 * Design references: §52 (C99, no compiler extensions in project-owned code),
 * §10 (platform macros isolated here, never sprinkled through HTTP logic).
 *
 * NOTHING below src/init.c may include R headers. This file is the boundary
 * that keeps the core compilable into a standalone fuzz harness (§11, §43).
 */
#ifndef ZUHTTP_PLATFORM_H
#define ZUHTTP_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#if defined(_WIN32) || defined(_WIN64)
#  define ZUH_WINDOWS 1
#else
#  define ZUH_POSIX 1
#endif

/* ssize_t is POSIX, not C99, and absent under MSVC. Own the signed size type
 * rather than depending on the platform to provide one. */
typedef ptrdiff_t zuh_ssize;
#define ZUH_SSIZE_MAX ((zuh_ssize)(SIZE_MAX / 2))

/* Format-string checking where the compiler supports it. */
#if defined(__GNUC__) || defined(__clang__)
#  define ZUH_PRINTF(fmt_idx, first_arg) __attribute__((format(printf, fmt_idx, first_arg)))
#else
#  define ZUH_PRINTF(fmt_idx, first_arg)
#endif

#define ZUH_UNUSED(x) ((void)(x))

#endif /* ZUHTTP_PLATFORM_H */
