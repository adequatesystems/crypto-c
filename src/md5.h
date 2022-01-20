/**
 * md5.h - MD5 hash function support header
 *
 * For more information, please refer to ./md5.c
 *
 * Date: 8 April 2020
 * Revised: 26 October 2021
 *
*/

#ifndef _CRYPTO_MD5_H_
#define _CRYPTO_MD5_H_  /* include guard */


#include <stddef.h>  /* for size_t */
#include "extint.h"  /* for word types */

/* 32-bit rotate left definition */
#ifndef ROTL32
#define ROTL32(a,b)  ( (a << b) | (a >> (32-b)) )
#endif

/* MD5 specific routines */
#define F(x,y,z)  ( (x & y) | (~x & z) )
#define G(x,y,z)  ( (x & z) | (y & ~z) )
#define H(x,y,z)  ( x ^ y ^ z )
#define I(x,y,z)  ( y ^ (x | ~z) )

#define FF(a,b,c,d,m,s,t)  { a += F(b,c,d) + m + t; a = b + ROTL32(a,s); }
#define GG(a,b,c,d,m,s,t)  { a += G(b,c,d) + m + t; a = b + ROTL32(a,s); }
#define HH(a,b,c,d,m,s,t)  { a += H(b,c,d) + m + t; a = b + ROTL32(a,s); }
#define II(a,b,c,d,m,s,t)  { a += I(b,c,d) + m + t; a = b + ROTL32(a,s); }

/* MD5 specific parameters */
#define MD5LEN  16

/* MD5 context */
typedef struct {
   word8 data[64];
   word32 datalen;
   word32 bitlen[2];
   word32 state[4];
} MD5_CTX;

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes for md5.c */
void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const void *in, size_t inlen);
void md5_final(MD5_CTX *ctx, void *out);
void md5(const void *in, size_t inlen, void *out);

#ifdef __cplusplus
}
#endif


#endif  /* end _CRYPTO_MD5_H_ */
