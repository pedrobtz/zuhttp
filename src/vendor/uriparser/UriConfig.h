/* UriConfig.h — authored by zuhttp, NOT vendored from upstream.
 *
 * Upstream generates this from src/UriConfig.h.in via CMake/autotools. zuhttp
 * has no configure step for it, so it is written by hand. Only one file in the
 * vendored subset includes it (UriMemory.c) and only one macro matters.
 *
 * HAVE_REALLOCARRAY is deliberately LEFT UNDEFINED. With it undefined,
 * uriDefaultReallocarray() computes nmemb*size and runs the library's own
 * URI_CHECK_ALLOC_OVERFLOW before calling realloc(). That path is portable to
 * every platform zuhttp targets and needs no probe, whereas defining the macro
 * would require reallocarray(3) (glibc >= 2.26, BSD) and would drag in
 * _GNU_SOURCE — which would collide with the feature-test macros zu_platform.h
 * sets for strict C99 (see the 2230b11 portability fix).
 *
 * HAVE_WPRINTF is irrelevant here: it is only used by the wide-char code, and
 * the subset is compiled ANSI-only (URI_NO_UNICODE).
 */
#ifndef URI_CONFIG_H
#define URI_CONFIG_H 1

#define PACKAGE_VERSION "0.9.8"

#endif /* URI_CONFIG_H */
