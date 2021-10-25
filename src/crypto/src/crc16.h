/**
 * crc16.h - CRC16 Hash function support header.
 *
 * Copyright (c) 2021 Adequate Systems, LLC. All Rights Reserved.
 * For more information, please refer to ../LICENSE
 *
 * Date: 19 August 2021
 *
*/

#ifndef _CRC16_H_
#define _CRC16_H_  /* include guard */


#include <stdint.h>
#include <stdio.h>

#ifndef CRC16LEN
#define CRC16LEN  2
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Compute CRC16 on "in" as array of 8-bit unsigned integers */
uint16_t crc16(void *in, size_t inlen);

#ifdef __cplusplus
}
#endif


#endif  /* end _CRC16_H_ */
