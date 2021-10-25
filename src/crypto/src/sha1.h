/**
 * sha1.h - SHA1 hash function support header.
 *
 * For more information, please refer to ./sha1.c
 *
 * Date: 8 April 2020
 * Revised: 19 August 2021
 *
*/

#ifndef _SHA1_H_
#define _SHA1_H_  /* include guard */


#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef SHA1LEN
#define SHA1LEN  20
#endif

#ifndef ROTL32
#define ROTL32(a,b)  ( ((a) << (b)) | ((a) >> (32-(b))) )
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* SHA1 context */
typedef struct {
   uint8_t data[64];
   uint32_t datalen;
   uint64_t bitlen;
   uint32_t state[5];
} SHA1_CTX;

/* SHA1 transformation */
void sha1_transform(SHA1_CTX *ctx, const uint8_t data[]);

/* Initialize the hashing context `ctx` */
void sha1_init(SHA1_CTX *ctx);

/* Add `inlen` bytes from `in` into the hash */
void sha1_update(SHA1_CTX *ctx, const void *in, size_t inlen);

/* Generate the message digest and place in `out` */
void sha1_final(SHA1_CTX *ctx, void *out);

/* Convenient all-in-one SHA1 computation */
void sha1(const void *in, size_t inlen, void *out);

#ifdef __cplusplus
}
#endif


#endif  /* end _SHA1_H_ */
