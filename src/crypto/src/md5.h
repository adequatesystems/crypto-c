/**
 * md5.h - MD5 hash function support header
 *
 * For more information, please refer to ./md5.c
 *
 * Date: 8 April 2020
 * Revised: 19 August 2021
 *
*/

#ifndef _MD5_H_
#define _MD5_H_  /* include guard */


#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef MD5LEN
#define MD5LEN  16
#endif

#ifndef ROTL32
#define ROTL32(a,b)  ( (a << b) | (a >> (32-b)) )
#endif

#define F(x,y,z)  ( (x & y) | (~x & z) )
#define G(x,y,z)  ( (x & z) | (y & ~z) )
#define H(x,y,z)  ( x ^ y ^ z )
#define I(x,y,z)  ( y ^ (x | ~z) )

#define FF(a,b,c,d,m,s,t)  { a += F(b,c,d) + m + t; a = b + ROTL32(a,s); }
#define GG(a,b,c,d,m,s,t)  { a += G(b,c,d) + m + t; a = b + ROTL32(a,s); }
#define HH(a,b,c,d,m,s,t)  { a += H(b,c,d) + m + t; a = b + ROTL32(a,s); }
#define II(a,b,c,d,m,s,t)  { a += I(b,c,d) + m + t; a = b + ROTL32(a,s); }

#ifdef __cplusplus
extern "C" {
#endif

/* MD5 context */
typedef struct {
   uint8_t data[64];
   uint32_t datalen;
   uint64_t bitlen;
   uint32_t state[4];
} MD5_CTX;

/* MD5 transformation */
void md5_transform(MD5_CTX *ctx, const uint8_t data[]);

/* Initialize the hashing context `ctx` */
void md5_init(MD5_CTX *ctx);

/* Add `inlen` bytes from `in` into the hash */
void md5_update(MD5_CTX *ctx, const void *in, size_t inlen);

/* Generate the message digest and place in `out` */
void md5_final(MD5_CTX *ctx, void *out);

/* Convenient all-in-one MD5 computation */
void md5(const void *in, size_t inlen, void *out);

#ifdef __cplusplus
}
#endif


#endif  /* end _MD5_H_ */
