/**
 * sha3.h - SHA3 and Keccak hash function support header
 *
 * For more information, please refer to ./sha3.c
 *
 * Date: 22 April 2020
 * Revised: 19 August 2021
 *
*/

#ifndef _SHA3_H_
#define _SHA3_H_  /* include guard */


#include <stddef.h>
#include <stdint.h>

#ifndef SHA3LEN224
#define SHA3LEN224  28
#endif

#ifndef SHA3LEN256
#define SHA3LEN256  32
#endif

#ifndef SHA3LEN384
#define SHA3LEN384  48
#endif

#ifndef SHA3LEN512
#define SHA3LEN512  64
#endif

#ifndef KECCAKLEN224
#define KECCAKLEN224  28
#endif

#ifndef KECCAKLEN256
#define KECCAKLEN256  32
#endif

#ifndef KECCAKLEN384
#define KECCAKLEN384  48
#endif

#ifndef KECCAKLEN512
#define KECCAKLEN512  64
#endif

#ifndef KECCAKF_ROUNDS
#define KECCAKF_ROUNDS  24
#endif

#ifndef ROTL64
#define ROTL64(x, y)  ( ((x) << (y)) | ((x) >> (64 - (y))) )
#endif

#define keccak_init(c, len)          sha3_init(c, len)
#define keccak_update(c, data, len)  sha3_update(c, data, len)

#ifdef __cplusplus
extern "C" {
#endif

/* SHA3 context */
typedef struct {
   union {               /* state:        */
      uint8_t b[200];    /*  8-bit bytes  */
      uint32_t d[50];    /*  32-bit words */
      uint64_t q[25];    /*  64-bit words */
   } st;
   int pt, rsiz, outlen;  /* these don't overflow */
} SHA3_CTX;
typedef SHA3_CTX  KECCAK_CTX;

/* SHA3_Keccak permutation */
void sha3_keccakf(uint64_t st[]);

/* Initialize the hashing context `ctx` */
void sha3_init(SHA3_CTX *ctx, int outlen);

/* Add `inlen` bytes from `in` into the hash */
void sha3_update(SHA3_CTX *ctx, const void *in, size_t inlen);

/* Generate the message digest and place in `out` */
void sha3_final(SHA3_CTX *ctx, void *out);
void keccak_final(SHA3_CTX *ctx, void *out);

/* Convenient all-in-one SHA3 computation */
void sha3(const void *in, size_t inlen, void *out, int outlen);

/* Convenient all-in-one Keccak computation */
void keccak(const void *in, size_t inlen, void *out, int outlen);

#ifdef __cplusplus
}
#endif


#endif  /* end _SHA3_H_ */
