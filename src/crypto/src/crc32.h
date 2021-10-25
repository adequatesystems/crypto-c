/**
 * crc32.h - CRC32 hash function support header
 *
 * Copyright (c) 2021 Adequate Systems, LLC. All Rights Reserved.
 * For more information, please refer to ../LICENSE
 *
 * Date: 19 August 2021
 *
*/

#ifndef _CRC32_H_
#define _CRC32_H_  /* include guard */


#include <stdint.h>
#include <stdio.h>

#ifndef CRC32LEN
#define CRC32LEN  4
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Compute CRC32 on "in" as array of 8-bit unsigned integers */
uint32_t crc32(void *in, size_t inlen);

#ifdef __cplusplus
}
#endif


#endif  /* end _CRC32_H_ */
