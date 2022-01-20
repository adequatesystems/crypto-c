/**
 * crc32.h - CRC32 hash function support header
 *
 * Copyright (c) 2021 Adequate Systems, LLC. All Rights Reserved.
 * For more information, please refer to ../LICENSE
 *
 * Date: 19 August 2021
 * Revised: 26 October 2021
 *
*/

#ifndef _CRYPTO_CRC32_H_
#define _CRYPTO_CRC32_H_  /* include guard */


#include <stddef.h>  /* for size_t */
#include "extint.h"  /* for word types */

/* CRC32 specific parameters */
#define CRC32LEN  4

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes for crc32.c */
word32 crc32(void *in, size_t inlen);

#ifdef __cplusplus
}
#endif


#endif  /* end _CRYPTO_CRC32_H_ */
