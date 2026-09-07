/*
 * zuhttp — Stage S1: Rtools / mingw-w64 Schannel header probe
 * See roadmap.md (S1) and zuhttp-design.md §47.4, Appendix B R-3.
 *
 * Question: does the mingw-w64 SDK shipped with current Rtools expose the
 * declarations needed for a TLS 1.3-capable Schannel client, or must
 * zuhttp declare them itself behind version guards?
 *
 * This file is macro-level detection only and is designed to ALWAYS
 * compile, so that it can report on what is missing. The companion
 * probe_struct.c deliberately fails to compile when SCH_CREDENTIALS is
 * absent; the workflow records that outcome separately.
 *
 * Build with the R toolchain, so we test what R actually uses:
 *   CC=$(R CMD config CC); $CC -o probe probe.c -lsecur32 -lcrypt32 -lws2_32
 */

#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <stdio.h>

#define REPORT(name, cond) \
    printf("  %-34s %s\n", name, (cond) ? "present" : "MISSING")

int main(void) {
    int missing = 0;

    printf("== zuhttp S1: Schannel header probe ==\n\n");

#ifdef __MINGW64_VERSION_MAJOR
    printf("toolchain: mingw-w64 %d.%d\n",
           __MINGW64_VERSION_MAJOR, __MINGW64_VERSION_MINOR);
#else
    printf("toolchain: not mingw-w64 (or version macros absent)\n");
#endif
#ifdef _WIN32_WINNT
    printf("_WIN32_WINNT: 0x%04X\n", (unsigned)_WIN32_WINNT);
#endif
#ifdef NTDDI_VERSION
    printf("NTDDI_VERSION: 0x%08lX\n", (unsigned long)NTDDI_VERSION);
#endif
    printf("\nTLS 1.3 path (SCH_CREDENTIALS, Win10 1809+):\n");

#ifdef SCH_CREDENTIALS_VERSION
    REPORT("SCH_CREDENTIALS_VERSION", 1);
#else
    REPORT("SCH_CREDENTIALS_VERSION", 0); missing++;
#endif

#ifdef SCH_USE_STRONG_CRYPTO
    REPORT("SCH_USE_STRONG_CRYPTO", 1);
#else
    REPORT("SCH_USE_STRONG_CRYPTO", 0); missing++;
#endif

#ifdef SP_PROT_TLS1_3_CLIENT
    REPORT("SP_PROT_TLS1_3_CLIENT", 1);
#else
    REPORT("SP_PROT_TLS1_3_CLIENT", 0); missing++;
#endif

#ifdef SCH_CRED_MAX_SUPPORTED_PARAMETERS
    REPORT("SCH_CRED_MAX_SUPPORTED_PARAMETERS", 1);
#else
    REPORT("SCH_CRED_MAX_SUPPORTED_PARAMETERS", 0); missing++;
#endif

#ifdef TLS_PARAMETERS_DISABLE_TLS_1_3
    REPORT("TLS_PARAMETERS_DISABLE_TLS_1_3", 1);
#else
    REPORT("TLS_PARAMETERS_DISABLE_TLS_1_3", 0);
#endif

    printf("\nTLS 1.2 fallback path (SCHANNEL_CRED, always required):\n");

#ifdef SCHANNEL_CRED_VERSION
    REPORT("SCHANNEL_CRED_VERSION", 1);
#else
    REPORT("SCHANNEL_CRED_VERSION", 0); missing++;
#endif

#ifdef SP_PROT_TLS1_2_CLIENT
    REPORT("SP_PROT_TLS1_2_CLIENT", 1);
#else
    REPORT("SP_PROT_TLS1_2_CLIENT", 0); missing++;
#endif

#ifdef UNISP_NAME_A
    REPORT("UNISP_NAME_A", 1);
#else
    REPORT("UNISP_NAME_A", 0); missing++;
#endif

    printf("\nChain validation (design §13.4, §14.3):\n");
#ifdef CERT_CHAIN_POLICY_SSL
    REPORT("CERT_CHAIN_POLICY_SSL", 1);
#else
    REPORT("CERT_CHAIN_POLICY_SSL", 0); missing++;
#endif
#ifdef CERT_STORE_PROV_MEMORY
    REPORT("CERT_STORE_PROV_MEMORY", 1);
#else
    REPORT("CERT_STORE_PROV_MEMORY", 0); missing++;
#endif

    printf("\nStruct/function availability (link + sizeof):\n");
    printf("  %-34s %u bytes\n", "sizeof(SCHANNEL_CRED)", (unsigned)sizeof(SCHANNEL_CRED));
    printf("  %-34s %u bytes\n", "sizeof(SecBuffer)", (unsigned)sizeof(SecBuffer));
    printf("  %-34s %u bytes\n", "sizeof(SecBufferDesc)", (unsigned)sizeof(SecBufferDesc));

    /* Prove the SSPI entry points actually link, not just parse. */
    {
        PSecurityFunctionTableA t = InitSecurityInterfaceA();
        printf("  %-34s %s\n", "InitSecurityInterfaceA()", t ? "linked, non-NULL" : "returned NULL");
        if (!t) missing++;
    }
    {
        HCERTSTORE s = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
                                     CERT_STORE_CREATE_NEW_FLAG, NULL);
        printf("  %-34s %s\n", "CertOpenStore(MEMORY)", s ? "ok" : "FAILED");
        if (s) CertCloseStore(s, 0); else missing++;
    }

    printf("\n== verdict ==\n");
    if (missing == 0)
        printf("All probed declarations present. TLS 1.3 Schannel path is available.\n");
    else
        printf("%d declaration(s) missing. See zuhttp-design.md Appendix B R-3:\n"
               "zuhttp must declare them locally behind version guards, or ship\n"
               "Windows TLS 1.2-only for v1.\n", missing);

    /* Always exit 0: this is a report, not a pass/fail gate. The workflow
     * records the output; a human decides. */
    return 0;
}
