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
#  define ZU_WINDOWS 1
#else
#  define ZU_POSIX 1
#endif

/* ssize_t is POSIX, not C99, and absent under MSVC. Own the signed size type
 * rather than depending on the platform to provide one. */
typedef ptrdiff_t zu_ssize;
#define ZU_SSIZE_MAX ((zu_ssize)(SIZE_MAX / 2))

/* Format-string checking where the compiler supports it. */
#if defined(__GNUC__) || defined(__clang__)
#  define ZU_PRINTF(fmt_idx, first_arg) __attribute__((format(printf, fmt_idx, first_arg)))
#else
#  define ZU_PRINTF(fmt_idx, first_arg)
#endif

#define ZU_UNUSED(x) ((void)(x))

#endif /* ZUHTTP_PLATFORM_H */
