#include "cert_helper.h"
#include "ossl_helper.h"
#include "constants.h"

X509* lpu_x509_parse_pem(char* certificate) {
    BIO* bio = BIO_new_mem_buf(certificate, strlen(certificate) + 1);
    if (!bio) {
        LpuOSSLPrintError("Failed to open PEM certificate")
        return NULL;
    }

    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        LpuOSSLPrintError("Failed to parse PEM certificate")
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);
    return cert;
}

X509* lpu_x509_load_pem(char* path) {
    BIO* bio = BIO_new_file(path, "r");
    if (!bio) {
        LpuOSSLPrintError("Failed to open PEM certificate: %s", path)
        return NULL;
    }

    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        LpuOSSLPrintError("Failed to parse PEM certificate: %s", path)
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);
    return cert;
}

X509* lpu_x509_parse_der(uint8_t* data, size_t len) {
    BIO* bio = BIO_new_mem_buf(data, len);
    if (!bio) {
        LpuOSSLPrintError("Failed to open DER certificate")
        return NULL;
    }

    const uint8_t* p = data;
    X509* cert = d2i_X509(NULL, &p, len);

    if (!cert) {
        LpuOSSLPrintError("Failed to parse DER certificate");
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);
    return cert;
}

struct lpu_trustchain* lpu_trustchain_new() {
    struct lpu_trustchain* chain = LpuAllocateStruct(lpu_trustchain);
    chain->trusted_ca = X509_STORE_new();
    chain->cert_chain = sk_X509_new_null();

    /* Add integrated CAs */

    
    return chain;
}

bool lpu_trustchain_add_intermediate_str(struct lpu_trustchain* chain, char* certificate) {
    sk_X509_push(chain->cert_chain, lpu_x509_parse_pem(certificate));

    return true;
}

bool lpu_trustchain_add_intermediate_der(struct lpu_trustchain* chain, uint8_t* data, size_t len) {
    sk_X509_push(chain->cert_chain, lpu_x509_parse_der(data, len));

    return true;
}

bool lpu_trustchain_add_intermediate(struct lpu_trustchain* chain, X509* certificate) {
    sk_X509_push(chain->cert_chain, certificate);

    return true;
}

bool lpu_trustchain_set_leaf_str(struct lpu_trustchain* chain, char* certificate) {
    chain->leaf = lpu_x509_parse_pem(certificate);

    return true;
}

bool lpu_trustchain_set_leaf_der(struct lpu_trustchain* chain, uint8_t* data, size_t len) {
    chain->leaf = lpu_x509_parse_der(data, len);
    
    return true;
}

bool lpu_trustchain_set_leaf(struct lpu_trustchain* chain, X509* certificate) {
    chain->leaf = certificate;

    return true;
}

int lpu_trustchain_verify(struct lpu_trustchain* chain) {
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, chain->trusted_ca, chain->leaf, chain->cert_chain);

    X509_verify_cert(ctx);
    int result = X509_STORE_CTX_get_error(ctx);

    X509_STORE_CTX_free(ctx);

    return result;
}

int lpu_trustchain_verifykey(struct lpu_trustchain* chain, EVP_PKEY* key) {
    EVP_PKEY* expected = X509_get_pubkey(chain->leaf);

    if (expected == NULL) {
        ConsoleWriteFAIL("Warning: Invalid certificate (No public key)")
        return false;
    }

    if (!EVP_PKEY_cmp(expected, key)) {
        return -100;
    }

    return lpu_trustchain_verify(chain);
}

void lpu_trustchain_free(struct lpu_trustchain* chain) {
    sk_X509_pop_free(chain->cert_chain, X509_free);
    X509_free(chain->leaf);
    X509_STORE_free(chain->trusted_ca);
    free(chain);
}