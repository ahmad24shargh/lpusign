#ifndef LPUSIGN_HEADER_CERT_HELPER_H
#define LPUSIGN_HEADER_CERT_HELPER_H

#include "prelude.h"

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>

struct lpu_trustchain {
    X509_STORE* trusted_ca;
    STACK_OF(X509)* cert_chain;
    X509* leaf;
};

X509* lpu_x509_parse_pem(char* certificate);
X509* lpu_x509_load_pem(char* path);
X509* lpu_x509_parse_der(uint8_t* data, size_t len);

struct lpu_trustchain* lpu_trustchain_new();
bool lpu_trustchain_add_intermediate_str(struct lpu_trustchain* chain, char* certificate);
bool lpu_trustchain_add_intermediate_der(struct lpu_trustchain* chain, uint8_t* data, size_t len);
bool lpu_trustchain_add_intermediate(struct lpu_trustchain* chain, X509* certificate);
bool lpu_trustchain_set_leaf_str(struct lpu_trustchain* chain, char* certificate);
bool lpu_trustchain_set_leaf_der(struct lpu_trustchain* chain, uint8_t* data, size_t len);
bool lpu_trustchain_set_leaf(struct lpu_trustchain* chain, X509* certificate);

/**
 * Verify certificate chain only.
 * If verification passed, return code is zero.
 * If verification failed, return codes are X509_V_ERR_<REASON>.
 */
int lpu_trustchain_verify(struct lpu_trustchain* chain);

/**
 * Verify certificate chain along with key.
 * If verification passed, return code is zero.
 * If public key mismatch, return code is -100.
 * If verification failed, return codes are X509_V_ERR_<REASON>.
 */
int lpu_trustchain_verifykey(struct lpu_trustchain* chain, EVP_PKEY* key);

void lpu_trustchain_free(struct lpu_trustchain* chain);


#endif