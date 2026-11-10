/* RFC 3986 §5.4, "Reference Resolution Examples": all 42 of them (#245).
 *
 * Provenance. Copied verbatim from https://www.rfc-editor.org/rfc/rfc3986.txt
 * (sha256 3102dae4b68cebe40337730312fcb612297b8928547267e8b3d1ee6002b2d683,
 * fetched 2026-11-10), §5.4.1 "Normal Examples" (23 rows) and §5.4.2
 * "Abnormal Examples" (19 rows), in the RFC's order, against the base
 * "http://a/b/c/d;p?q". For "http:g" the strict-parser result is the one
 * listed, because §19.6 resolves "RFC 3986 §5.2.2 strict". Do not edit a row:
 * a row zuhttp answers differently is marked in test_uri.c, not here.
 *
 * Kept as data rather than code so the test cannot be bent to the
 * implementation: test_uri.c derives what zuhttp's flat zuh_uri should hold
 * from the RFC's own result string. */
#ifndef ZUHTTP_CTEST_RFC3986_EXAMPLES_H
#define ZUHTTP_CTEST_RFC3986_EXAMPLES_H

#define RFC3986_BASE "http://a/b/c/d;p?q"

typedef struct {
    const char *section;   /* "5.4.1" or "5.4.2" */
    const char *ref;
    const char *result;
} rfc3986_example;

static const rfc3986_example rfc3986_examples[] = {
    /* §5.4.1 Normal Examples */
    {"5.4.1", "g:h",           "g:h"},
    {"5.4.1", "g",             "http://a/b/c/g"},
    {"5.4.1", "./g",           "http://a/b/c/g"},
    {"5.4.1", "g/",            "http://a/b/c/g/"},
    {"5.4.1", "/g",            "http://a/g"},
    {"5.4.1", "//g",           "http://g"},
    {"5.4.1", "?y",            "http://a/b/c/d;p?y"},
    {"5.4.1", "g?y",           "http://a/b/c/g?y"},
    {"5.4.1", "#s",            "http://a/b/c/d;p?q#s"},
    {"5.4.1", "g#s",           "http://a/b/c/g#s"},
    {"5.4.1", "g?y#s",         "http://a/b/c/g?y#s"},
    {"5.4.1", ";x",            "http://a/b/c/;x"},
    {"5.4.1", "g;x",           "http://a/b/c/g;x"},
    {"5.4.1", "g;x?y#s",       "http://a/b/c/g;x?y#s"},
    {"5.4.1", "",              "http://a/b/c/d;p?q"},
    {"5.4.1", ".",             "http://a/b/c/"},
    {"5.4.1", "./",            "http://a/b/c/"},
    {"5.4.1", "..",            "http://a/b/"},
    {"5.4.1", "../",           "http://a/b/"},
    {"5.4.1", "../g",          "http://a/b/g"},
    {"5.4.1", "../..",         "http://a/"},
    {"5.4.1", "../../",        "http://a/"},
    {"5.4.1", "../../g",       "http://a/g"},
    /* §5.4.2 Abnormal Examples */
    {"5.4.2", "../../../g",    "http://a/g"},
    {"5.4.2", "../../../../g", "http://a/g"},
    {"5.4.2", "/./g",          "http://a/g"},
    {"5.4.2", "/../g",         "http://a/g"},
    {"5.4.2", "g.",            "http://a/b/c/g."},
    {"5.4.2", ".g",            "http://a/b/c/.g"},
    {"5.4.2", "g..",           "http://a/b/c/g.."},
    {"5.4.2", "..g",           "http://a/b/c/..g"},
    {"5.4.2", "./../g",        "http://a/b/g"},
    {"5.4.2", "./g/.",         "http://a/b/c/g/"},
    {"5.4.2", "g/./h",         "http://a/b/c/g/h"},
    {"5.4.2", "g/../h",        "http://a/b/c/h"},
    {"5.4.2", "g;x=1/./y",     "http://a/b/c/g;x=1/y"},
    {"5.4.2", "g;x=1/../y",    "http://a/b/c/y"},
    {"5.4.2", "g?y/./x",       "http://a/b/c/g?y/./x"},
    {"5.4.2", "g?y/../x",      "http://a/b/c/g?y/../x"},
    {"5.4.2", "g#s/./x",       "http://a/b/c/g#s/./x"},
    {"5.4.2", "g#s/../x",      "http://a/b/c/g#s/../x"},
    {"5.4.2", "http:g",        "http:g"}
};

#define RFC3986_N_EXAMPLES (sizeof rfc3986_examples / sizeof rfc3986_examples[0])

#endif /* ZUHTTP_CTEST_RFC3986_EXAMPLES_H */
