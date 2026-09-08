/* Exactly the OpenSSL surface zu_tls_openssl.c uses — no more. */
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/bio.h>
int main(void) {
    SSL_CTX *c = SSL_CTX_new(TLS_client_method());
    SSL *s; BIO *rb, *wb; X509 *cert; X509_VERIFY_PARAM *p;
    SSL_CTX_set_verify(c, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION);
    SSL_CTX_set_default_verify_paths(c);
    SSL_CTX_load_verify_locations(c, "x", NULL);
    s = SSL_new(c);
    p = SSL_get0_param(s);
    X509_VERIFY_PARAM_set1_host(p, "example.com", 0);
    SSL_set_tlsext_host_name(s, "example.com");
    rb = BIO_new(BIO_s_mem()); wb = BIO_new(BIO_s_mem());
    SSL_set_bio(s, rb, wb);
    SSL_connect(s); SSL_read(s, NULL, 0); SSL_write(s, NULL, 0); SSL_shutdown(s);
    cert = SSL_get1_peer_certificate(s);
    if (cert) { X509_digest(cert, EVP_sha256(), NULL, NULL); X509_free(cert); }
    SSL_get_verify_result(s);
    SSL_get_version(s); SSL_get_cipher_name(s);
    ERR_get_error(); ERR_error_string_n(0, NULL, 0);
    SSL_free(s); SSL_CTX_free(c);
    return 0;
}
