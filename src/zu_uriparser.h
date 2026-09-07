/* zuhttp — the single place that includes the vendored uriparser (§48).
 *
 * Both flags below MUST be set before <uriparser/Uri.h> is read. Setting them
 * here rather than only in the build files means a translation unit is correct
 * even if a Makefile forgets them; see src/vendor/uriparser/VENDOR.
 *
 * Nothing outside src/zu_uri.c should include this. The rest of zuhttp talks
 * to the flat zu_uri struct, which is what keeps the parser replaceable.
 */
#ifndef ZUHTTP_URIPARSER_H
#define ZUHTTP_URIPARSER_H

#ifndef URI_NO_UNICODE
#  define URI_NO_UNICODE 1   /* ANSI only: drops the wchar_t half and <wchar.h> */
#endif
#ifndef URI_STATIC_BUILD
#  define URI_STATIC_BUILD 1 /* MSVC only; stops __declspec(dllimport) */
#endif

#include <uriparser/Uri.h>

#endif /* ZUHTTP_URIPARSER_H */
