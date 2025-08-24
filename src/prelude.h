#ifndef LPUSIGN_HEADER_PRELUDE_H
#define LPUSIGN_HEADER_PRELUDE_H

#define LPU_LIBRARY_VERSION_STRING "1.0"
/**
 * Valid version types are:
 *  'stable', 'staging', 'dev'
 */
#define LPU_LIBRARY_VERSION_TYPE "staging"

#if __has_include(<unistd.h>)
#define LPU_TARGET_POSIX 1
#endif

#if defined(_WIN64)
#define LPU_TARGET_NT 1
#endif 

#if defined(__APPLE__)
#define LPU_TARGET_APPLE 1
#define LPU_TARGET_POSIX 1
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define __hide __attribute__((visibility("hidden")))

#include "sys.h"
#include "utils.h"

#endif
