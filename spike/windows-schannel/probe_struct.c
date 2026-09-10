/*
 * zuhttp — Stage S1 companion probe.
 *
 * Unlike probe.c, this file is MEANT to fail compilation when the Rtools
 * mingw-w64 SDK lacks the TLS 1.3 Schannel declarations. `SCH_CREDENTIALS`
 * is a typedef, not a macro, so #ifdef cannot detect it — only a real use
 * can. The workflow compiles this with -fsyntax-only and records whether
 * it succeeded.
 *
 *   success => Rtools has the TLS 1.3 path; Appendix B R-3 is retired.
 *   failure => zuhttp must declare these itself, or ship TLS 1.2-only.
 */

#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <sspi.h>
#include <schannel.h>

/* The TLS 1.3-capable credential structure. */
static SCH_CREDENTIALS  g_cred;
static TLS_PARAMETERS   g_params;

/* Compile-time assertions that the fields zuhttp actually needs exist. */
typedef char assert_cred_version[ (SCH_CREDENTIALS_VERSION >= 5) ? 1 : -1 ];

int probe_struct_fields(void);

int probe_struct_fields(void) {
    g_cred.dwVersion             = SCH_CREDENTIALS_VERSION;
    g_cred.dwFlags               = SCH_USE_STRONG_CRYPTO;
    g_cred.cTlsParameters        = 1;
    g_cred.pTlsParameters        = &g_params;

    g_params.grbitDisabledProtocols = 0;
    g_params.cAlpnIds               = 0;

    return (int)(g_cred.dwVersion + g_params.cAlpnIds);
}
