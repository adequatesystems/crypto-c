/**
 * sha256.h - SHA256 hash function support header
 *
 * For more information, please refer to ./sha256.c
 *
 * Date: 8 April 2020
 * Revised: 19 August 2021
 *
*/

#ifndef _SHA256_H_
#define _SHA256_H_  /* include guard */


#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef SHA256LEN
#define SHA256LEN  32
#endif

#ifndef SHA256_ROUNDS
#define SHA256_ROUNDS  64
#endif

#ifndef ROTR32
#define ROTR32(a,b)  ( ((a) >> (b)) | ((a) << (32-(b))) )
#endif

#define CH(x,y,z)  ( ((x) & (y)) ^ (~(x) & (z)) )
#define MAJ(x,y,z)  ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)) )
#define EP0(x)  ( ROTR32(x,2) ^ ROTR32(x,13) ^ ROTR32(x,22) )
#define EP1(x)  ( ROTR32(x,6) ^ ROTR32(x,11) ^ ROTR32(x,25) )
#define SIG0(x)  ( ROTR32(x,7) ^ ROTR32(x,18) ^ ((x) >> 3) )
#define SIG1(x)  ( ROTR32(x,17) ^ ROTR32(x,19) ^ ((x) >> 10) )

#ifdef __cplusplus
extern "C" {
#endif

/* SHA256 context */
typedef struct {
   uint8_t data[64];
   uint32_t datalen;
   uint64_t bitlen;
   uint32_t state[8];
} SHA256_CTX;

/* SHA256 transformation */
void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]);

/* Initialize the hashing context `ctx` */
void sha256_init(SHA256_CTX *ctx);

/* Add `inlen` bytes from `in` into the hash */
void sha256_update(SHA256_CTX *ctx, const void *in, size_t inlen);

/* Generate the message digest and place in `out` */
void sha256_final(SHA256_CTX *ctx, void *out);

/* Convenient all-in-one SHA256 computation */
void sha256(const void *in, size_t inlen, void *out);

#ifdef __cplusplus
}
#endif


#endif  /* end _SHA256_H_ */