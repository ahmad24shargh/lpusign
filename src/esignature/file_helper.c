#include "file_helper.h"

#include <openssl/err.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "ed25519_sign.h"


static char* error_messages[] = {
    "Failed to map input file into memory (out of memory?)",
    "Input file does not have a valid E-Signature header"
};

bool lpu_file_sign(file_handle_t fd, EVP_PKEY* key, uint8_t* result, uint8_t* hash) {

    size_t buf_sz = lpu_sys_file_sz(fd);

    void* buffer = lpu_sys_file_map(fd, buf_sz);
    
    lpu_hash_buffer(buffer, buf_sz, hash);

    if (!lpu_sign_buffer(key, hash, LPU_HASH_LENGTH, result)) {
        LpuOSSLPrintError("Failed to sign buffer!");
    }

    lpu_sys_file_unmap(buffer, buf_sz);

    return true;
}

bool lpu_file_write_esig(file_handle_t fd, struct lpu_esignature* esignature, size_t len) {
    if (lseek(fd, 0, SEEK_END) == -1) {
        return false;
    }

    uint64_t magic = LPU_ESIGNATURE_MAGIC;

    lpu_sys_file_append_end(fd, (uint8_t*) esignature, len);
    lpu_sys_file_append_end(fd, (uint8_t*) &len, sizeof(size_t));
    lpu_sys_file_append_end(fd, (uint8_t*) &magic, sizeof(uint64_t));

    return true;
}

struct lpu_esignature* lpu_file_read_esig(file_handle_t fd) {
    struct lpu_esignature* esign_buf = NULL;

    size_t file_sz = lpu_sys_file_sz(fd);

    void* buffer = lpu_sys_file_map(fd, file_sz);

    if (buffer == NULL) {
        goto done;
    }

    void* buff_end = ApplyOffset(buffer, +(file_sz));
    uint64_t* r_magic = (uint64_t*) ApplyOffset(buff_end, -8);
    
    if (*r_magic != LPU_ESIGNATURE_MAGIC) {
        goto done;
    }
    
    uint64_t* sz = (uint64_t*) ApplyOffset(buff_end, -16);
    if (*sz == 0 || *sz > file_sz) {
        goto done;
    }

    esign_buf = (struct lpu_esignature*) ApplyOffset(sz, -*sz);

    if (esign_buf->magic != LPU_ESIGNATURE_MAGIC || esign_buf->version != LPU_ESIGNATURE_VERSION) {
        goto done;
    }

    lpu_mdupfield((void**) &esign_buf, *sz);

done:
    lpu_sys_file_unmap(buffer, file_sz);
    return esign_buf;
}

uint32_t lpu_file_verify_esig(file_handle_t fd, uint32_t flags) {
    size_t file_sz = lpu_sys_file_sz(fd);

    void* buffer = lpu_sys_file_map(fd, file_sz);

    if (buffer == NULL) {
        return LPU_FV_MMAP_FAILED;
    }

    void* buff_end = ApplyOffset(buffer, +(file_sz));
    uint64_t* r_magic = (uint64_t*) ApplyOffset(buff_end, -8);
    
    if (*r_magic != LPU_ESIGNATURE_MAGIC) {
        return LPU_FV_INVALID_HEADER;
    }

    uint64_t* sz = (uint64_t*) ApplyOffset(buff_end, -16);
    if (*sz == 0 || *sz > file_sz) {
        return LPU_FV_INVALID_HEADER;
    }

    struct lpu_esignature* esign_buf = (struct lpu_esignature*) ApplyOffset(sz, -*sz);

    /* Entire file footer is ESignature + ESignatureSize + ESignatureMagic 
         which is *sz + sizeof(sz) + 8 = *sz + 16
       So, original file buffer will be FileSize - *sz - 16 */
    uint32_t result = lpu_esign_verify(esign_buf, buffer, file_sz - *sz - 16, flags);

    lpu_sys_file_unmap(buffer, file_sz);
    return result;
}

const char* lpu_file_verrcidx2str(uint8_t idx) {
    if (idx < 16) {
        return lpu_esign_verrcidx2str(idx);
    }

    if (idx >= 31) {
        return NULL;
    }

    return error_messages[idx - 16];
}
