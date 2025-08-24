#ifndef LPUSIGN_HEADER_FILE_HELPER_H
#define LPUSIGN_HEADER_FILE_HELPER_H

#include "prelude.h"
#include "hasher.h"
#include "esignature.h"

#include <openssl/evp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define LPU_FV_MMAP_FAILED    (1 << 16)
#define LPU_FV_INVALID_HEADER (1 << 17)

bool lpu_file_sign(file_handle_t fd, EVP_PKEY* key, uint8_t* result, uint8_t* hash);
bool lpu_file_write_esig(file_handle_t fd, struct lpu_esignature* esignature, size_t len);

uint32_t lpu_file_verify_esig(file_handle_t fd, uint32_t flags);

struct lpu_esignature* lpu_file_read_esig(file_handle_t fd);

/**
 * Get error message based on verification error code bit field index.
 * Call this function instead of lpu_esign_verrcidx2str to get messages like LPU_FV_MMAP_FAILED.
 */
const char* lpu_file_verrcidx2str(uint8_t idx);

#endif