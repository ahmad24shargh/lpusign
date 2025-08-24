#ifndef LPUSIGN_HEADER_CONSTANTS_H
#define LPUSIGN_HEADER_CONSTANTS_H

#include "prelude.h"

#define LpuDefineConstant(file) \
    extern const uint8_t const_##file[]; \
    extern const uint8_t const_##file##_end[]; \
    extern const size_t const_##file##_sz;

#define LpuDefineStrConstant(file) \
    extern const char* const_##file; \
    extern const char* const_##file##_end; \
    extern const size_t const_##file##_sz;

#define LpuConstant(file) const_##file
#define LpuConstantSz(file) const_##file##_sz

LpuDefineConstant(help);

/* Add integrated CAs */


#endif