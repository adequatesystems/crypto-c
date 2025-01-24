/**
 * @file base58.h
 * @brief Base58 encode/decode function support.
 * @copyright This file is released into the Public Domain under
 * the Creative Commons Zero v1.0 Universal license.
 */

/* include guard */
#ifndef CRYPTO_BASE58_H
#define CRYPTO_BASE58_H


#include <stddef.h>

/* C/C++ compatible function prototypes */
#ifdef __cplusplus
extern "C" {
#endif

int base58_encode(const void *in, size_t inlen, char *out);
int base58_decode(const char* in, void *out);

/* end extern "C" {} for C++ */
#ifdef __cplusplus
}
#endif

/* end include guard */
#endif
