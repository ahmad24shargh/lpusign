#ifndef LPUSIGN_HEADER_ESIGNATURE_H
#define LPUSIGN_HEADER_ESIGNATURE_H

#include "prelude.h"
#include "cert_helper.h"

#define LPU_SIGNATURE_LENGTH 64
#define LPU_PUBKEY_LENGTH 32
#define LPU_HASH_LENGTH 32
#define LPU_MAX_CERITIFICATE_CHAIN 3

#define LPU_ESIGNATURE_MAGIC 0x7a616b6f7369676eull
#define LPU_ESIGNATURE_VERSION 1

#define LPU_ESV_STRICT_MODE    (1 << 0)
#define LPU_ESV_INTEGRITY_ONLY (1 << 1)

#define LPU_ESV_IMPORTANT_ERROR (1 << 31)

#define LPU_ESV_INVALID_HEADER            (1 <<  0) + LPU_ESV_IMPORTANT_ERROR
#define LPU_ESV_UNSUPPORTED_VERSION       (1 <<  2) + LPU_ESV_IMPORTANT_ERROR
#define LPU_ESV_OUTDATED_VERSION          (1 <<  3) + LPU_ESV_IMPORTANT_ERROR
#define LPU_ESV_MISSING_CERTIFICATE       (1 <<  4)
#define LPU_ESV_UNTRUST_CERTIFICATE_CHAIN (1 <<  5) + LPU_ESV_IMPORTANT_ERROR
#define LPU_ESV_MISSING_TIMESTAMP         (1 <<  6)
#define LPU_ESV_UNTRUSTED_TIMESTAMP       (1 <<  7) + LPU_ESV_IMPORTANT_ERROR
#define LPU_ESV_VERFICATION_FAILED        (1 <<  8) + LPU_ESV_IMPORTANT_ERROR
#define LPU_ESV_CERTIFICATE_EXPIRED       (1 <<  9)
#define LPU_ESV_CERTIFICATE_ERROR         (1 <<  9)
#define LPU_ESV_CERTKEY_MISMATCH          (1 << 10) + LPU_ESV_IMPORTANT_ERROR

struct lpu_der_certificate {
    /**
     * The id of this ceritificate
     */
    uint8_t id;

    /**
     * The size of this ceritificate
     */
    size_t len;
    uint8_t data[];
};

struct lpu_custom_field {
    /**
     * Non-duplicate field identifier
     */
    uint8_t id;
    size_t sz;

    uint8_t data[];
};

/**
 * The ceritificate chain for public_key
 */
struct lpu_keychain {
    uint8_t public_key[LPU_PUBKEY_LENGTH];

    /**
     * The id of ceritificate in certificate_store
     * Leaf certificate comes the first, and does not contains any RootCA
     * 
     * 255 means empty
     */
    uint8_t trustchain[LPU_MAX_CERITIFICATE_CHAIN];
};

/**
 * The structure for an esignature
 */
struct lpu_esignature {

    /**
     * Struct identifier
     */
    uint64_t magic;

    /**
     * Version
     */
    uint64_t version;

    /**
     * The signing key, including signature chain
     */
    struct lpu_keychain key;

    /**
     * Buffer SHA256 hash
     */
    uint8_t hash[LPU_HASH_LENGTH];

    /**
     * Signature of data
     */
    uint8_t signature[LPU_SIGNATURE_LENGTH];
    
    /**
     * Signature signed date
     */
    uint64_t created_at;

    /**
     * # of certificates
     */
    uint8_t cert_sz;

    /**
     * # of extra fields
     */
    uint8_t extra_fields_sz;

    /**
     * Extra data for certificate store and extra fields
     * Certificats are always stored before extra fields
     * 
     * Valid types are either lpu_der_certificate or lpu_custom_field
     */
    uint8_t data[];
};

struct lpu_esign_context {
    /**
     * Certificate store
     */
    struct lpu_der_certificate* certs[200];

    /**
     * # of certificates in certificate store
     */
    uint8_t cert_count;

    struct lpu_custom_field* extra_fields[256];

    /**
     * # of custom fields in extra fields
     */
    uint8_t extra_fields_count;

    /**
     * Internal buffer
     */
    struct lpu_esignature esig_buf;
};

struct lpu_esign_context* lpu_esign_new();

/**
 * Adds a certificate to certificate store and returns the id of the input certificate
 * LpuRootCA is built in, and you don't have to include it.
 * 
 * Capacity is capped at 200 certificates. Upon exceed, 255 is returned.
 * If X509 to DER failed, 254 is returned. 
 */
uint8_t lpu_esign_add_certificate(struct lpu_esign_context* ctx, X509* certificate);

/**
 * Add certificate to trust chain of the public key.
 * Call lpu_esign_add_certificate to obtain an ID for your certificate.
 */
void lpu_esign_add_keycert(struct lpu_esign_context* ctx, uint8_t id);

/**
 * Set public key
 */
void lpu_esign_set_publickey(struct lpu_esign_context* ctx, EVP_PKEY* key);

/**
 * Set signature
 */
void lpu_esign_set_signature(struct lpu_esign_context* ctx, uint8_t* hash, uint8_t* signature);

/**
 * esignature will be created and esign will be free-ed
 */
struct lpu_esignature* lpu_esign_create(struct lpu_esign_context* ctx, size_t* len);

uint32_t lpu_esign_verify(struct lpu_esignature* esig, uint8_t* buff, size_t len, uint32_t flags);

/**
 * Get error message based on verification error code bit field index
 */
const char* lpu_esign_verrcidx2str(uint8_t idx);

#endif
