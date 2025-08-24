#ifndef LPUSIGN_HEADER_HASHER_H
#define LPUSIGN_HEADER_HASHER_H

#include "prelude.h"
#include "ossl_helper.h"

#include <openssl/sha.h>

#define LPU_HASHER_SIZE SHA256_DIGEST_LENGTH

struct lpu_hash_stream {
    SHA256_CTX* ctx;
};

/**
 * Oneshot hash buffer and write generated hash into result
 */
bool lpu_hash_buffer(uint8_t* buffer, size_t len, uint8_t* result);

/**
 * Verify buffer with given hash
 */
bool lpu_hash_verify(uint8_t* buffer, size_t len, uint8_t* sha256);

/**
 * Create new hash stream.
 */
struct lpu_hash_stream* lpu_hash_stream_new();

/**
 * Stream hash multiple buffers.
 * Pass NULL to buffer to do final and write generated hash into result.
 */
bool lpu_hash_stream(struct lpu_hash_stream* stream, uint8_t* buffer, size_t len, uint8_t* result);

#endif