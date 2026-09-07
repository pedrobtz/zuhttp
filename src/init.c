/* zuhttp — R entry points.
 *
 * Design §11: this is the ONLY file permitted to include R headers. Every
 * other translation unit under src/ is plain C, which is what allows the core
 * to link into ctest/ and, later, a fuzz harness with no R runtime present.
 * If you find yourself adding <R.h> to another file, the layering is wrong.
 *
 * S2 registers no routines yet: the foundations (allocator, buffer, error,
 * clock, stream, mock stream) are exercised by ctest/, not from R. R-visible
 * entry points arrive with S11.
 */
#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>
#include <R_ext/Visibility.h>

static const R_CallMethodDef call_methods[] = {
    {NULL, NULL, 0}
};

void attribute_visible R_init_zuhttp(DllInfo *dll) {
    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);
}
