/**
 * @private
 * @headerfile sha1.cuh <sha1.cuh>
 * @copyright This file is released into the Public Domain under
 * the Creative Commons Zero v1.0 Universal license.
*/

/* include guard */
#ifndef CRYPTO_SHA1_CU
#define CRYPTO_SHA1_CU


#include "sha1.cuh"
#include <string.h>

/**
 * @private
 * SHA1 transformation rounds.
 * @param ctx Pointer to SHA1 context
 * @param data Pointer to input to be transformed
*/
__device__ void cu_sha1_transform(SHA1_CTX *ctx, const uint8_t data[])
{
   /**
    * @private
    * SHA1 transformation constant.
   */
   __device__ __constant__ __align__(32) static uint32_t k[4] = {
      0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
   };

   __align__(8) uint32_t W[16];
   uint32_t a, b, c, d, e;

   /* copy data into intermediate state */
   memcpy(W, data, 64);

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

	/* SHA1 round 1 */
   sha1_r0(a, b, c, d, e, 0);
   sha1_r0(e, a, b, c, d, 1);
   sha1_r0(d, e, a, b, c, 2);
   sha1_r0(c, d, e, a, b, 3);
   sha1_r0(b, c, d, e, a, 4);
   sha1_r0(a, b, c, d, e, 5);
   sha1_r0(e, a, b, c, d, 6);
   sha1_r0(d, e, a, b, c, 7);
   sha1_r0(c, d, e, a, b, 8);
   sha1_r0(b, c, d, e, a, 9);
   sha1_r0(a, b, c, d, e, 10);
   sha1_r0(e, a, b, c, d, 11);
   sha1_r0(d, e, a, b, c, 12);
   sha1_r0(c, d, e, a, b, 13);
   sha1_r0(b, c, d, e, a, 14);
   sha1_r0(a, b, c, d, e, 15);
   /* alternate round computation */
   sha1_r1(e, a, b, c, d, 16);
   sha1_r1(d, e, a, b, c, 17);
   sha1_r1(c, d, e, a, b, 18);
   sha1_r1(b, c, d, e, a, 19);
   sha1_r2(a, b, c, d, e, 20);

	/* SHA1 round 2 */
   sha1_r2(e, a, b, c, d, 21);
   sha1_r2(d, e, a, b, c, 22);
   sha1_r2(c, d, e, a, b, 23);
   sha1_r2(b, c, d, e, a, 24);
   sha1_r2(a, b, c, d, e, 25);
   sha1_r2(e, a, b, c, d, 26);
   sha1_r2(d, e, a, b, c, 27);
   sha1_r2(c, d, e, a, b, 28);
   sha1_r2(b, c, d, e, a, 29);
   sha1_r2(a, b, c, d, e, 30);
   sha1_r2(e, a, b, c, d, 31);
   sha1_r2(d, e, a, b, c, 32);
   sha1_r2(c, d, e, a, b, 33);
   sha1_r2(b, c, d, e, a, 34);
   sha1_r2(a, b, c, d, e, 35);
   sha1_r2(e, a, b, c, d, 36);
   sha1_r2(d, e, a, b, c, 37);
   sha1_r2(c, d, e, a, b, 38);
   sha1_r2(b, c, d, e, a, 39);

	/* SHA1 round 3 */
   sha1_r3(a, b, c, d, e, 40);
   sha1_r3(e, a, b, c, d, 41);
   sha1_r3(d, e, a, b, c, 42);
   sha1_r3(c, d, e, a, b, 43);
   sha1_r3(b, c, d, e, a, 44);
   sha1_r3(a, b, c, d, e, 45);
   sha1_r3(e, a, b, c, d, 46);
   sha1_r3(d, e, a, b, c, 47);
   sha1_r3(c, d, e, a, b, 48);
   sha1_r3(b, c, d, e, a, 49);
   sha1_r3(a, b, c, d, e, 50);
   sha1_r3(e, a, b, c, d, 51);
   sha1_r3(d, e, a, b, c, 52);
   sha1_r3(c, d, e, a, b, 53);
   sha1_r3(b, c, d, e, a, 54);
   sha1_r3(a, b, c, d, e, 55);
   sha1_r3(e, a, b, c, d, 56);
   sha1_r3(d, e, a, b, c, 57);
   sha1_r3(c, d, e, a, b, 58);
   sha1_r3(b, c, d, e, a, 59);

	/* SHA1 round 4 */
   sha1_r4(a, b, c, d, e, 60);
   sha1_r4(e, a, b, c, d, 61);
   sha1_r4(d, e, a, b, c, 62);
   sha1_r4(c, d, e, a, b, 63);
   sha1_r4(b, c, d, e, a, 64);
   sha1_r4(a, b, c, d, e, 65);
   sha1_r4(e, a, b, c, d, 66);
   sha1_r4(d, e, a, b, c, 67);
   sha1_r4(c, d, e, a, b, 68);
   sha1_r4(b, c, d, e, a, 69);
   sha1_r4(a, b, c, d, e, 70);
   sha1_r4(e, a, b, c, d, 71);
   sha1_r4(d, e, a, b, c, 72);
   sha1_r4(c, d, e, a, b, 73);
   sha1_r4(b, c, d, e, a, 74);
   sha1_r4(a, b, c, d, e, 75);
   sha1_r4(e, a, b, c, d, 76);
   sha1_r4(d, e, a, b, c, 77);
   sha1_r4(c, d, e, a, b, 78);
   sha1_r4(b, c, d, e, a, 79);

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}  /* end cu_sha1_transform() */

/**
 * Initialize a SHA1 context.
 * @param ctx Pointer to SHA1 context
*/
__device__ void cu_sha1_init(SHA1_CTX *ctx)
{
   ctx->datalen = 0;
   ctx->bitlen[0] = ctx->bitlen[1] = 0;
   ctx->state[0] = 0x67452301;
   ctx->state[1] = 0xEFCDAB89;
   ctx->state[2] = 0x98BADCFE;
   ctx->state[3] = 0x10325476;
   ctx->state[4] = 0xc3d2e1f0;
}  /* end cu_sha1_init() */

/**
 * Add @a inlen bytes from @a in to a SHA1 context for hashing.
 * @param ctx Pointer to SHA1 context
 * @param in Pointer to data to hash
 * @param inlen Length of @a in data, in bytes
*/
__device__ void cu_sha1_update(SHA1_CTX *ctx, const void *in, size_t inlen)
{
   size_t i, n;
   uint32_t old;

   for(i = n = 0; inlen; i += n, inlen -= n) {
      /* copy memory to input buffer in chunks */
      n = (ctx->datalen + inlen) > 64 ? 64 - ctx->datalen : inlen;
      memcpy(ctx->data + ctx->datalen, (const uint8_t *) in + i, n);
      ctx->datalen += n;
      /* process input buffer */
      if (ctx->datalen == 64) {
         cu_sha1_transform(ctx, ctx->data);
         ctx->datalen = 0;
         old = ctx->bitlen[0];
         ctx->bitlen[0] += 512;
         if (ctx->bitlen[0] < old) ctx->bitlen[1]++;  /* add in carry */
      }
   }
}  /* end cu_sha1_update() */

/**
 * Finalize a SHA1 message digest.
 * Generate the SHA1 message digest and place in @a out.
 * @param ctx Pointer to SHA1 context
 * @param out Pointer to location to place the message digest
*/
__device__ void cu_sha1_final(SHA1_CTX *ctx, void *out)
{
   uint32_t i, old;

   i = ctx->datalen;

   /* Pad whatever data is left in the buffer. */
   if (ctx->datalen < 56) {
      ctx->data[i++] = 0x80;
      memset(ctx->data + i, 0, 64 - i);
   } else if (ctx->datalen >= 56) {
      ctx->data[i++] = 0x80;
      if (i < 64) memset(ctx->data + i, 0, 64 - i);
      cu_sha1_transform(ctx, ctx->data);
      memset(ctx->data, 0, 56);
   }

   /* Append to the padding the total message's length in bits and
    * transform (big endian). */
   old = ctx->bitlen[0];
   ctx->bitlen[0] += (uint32_t) ctx->datalen << 3;
   if(ctx->bitlen[0] < old) ctx->bitlen[1]++;  /* add in carry */
   /* immitate bswap64() for bitlen */
   ((uint32_t *) ctx->data)[15] = bswap32(ctx->bitlen[0]);
   ((uint32_t *) ctx->data)[14] = bswap32(ctx->bitlen[1]);
   cu_sha1_transform(ctx, ctx->data);

   /* Since this implementation uses little endian byte ordering and
    * SHA uses big endian, reverse all the bytes when copying the
    * final state to the output hash. */
   ((uint32_t *) out)[0] = bswap32(ctx->state[0]);
   ((uint32_t *) out)[1] = bswap32(ctx->state[1]);
   ((uint32_t *) out)[2] = bswap32(ctx->state[2]);
   ((uint32_t *) out)[3] = bswap32(ctx->state[3]);
   ((uint32_t *) out)[4] = bswap32(ctx->state[4]);
}  /* end cu_sha1_final() */

/**
 * Convenient all-in-one SHA1 computation.
 * Performs cu_sha1_init(), cu_sha1_update() and cu_sha1_final(),
 * and places the resulting hash in @a out.
 * @param in Pointer to data to hash
 * @param inlen Length of @a in data, in bytes
 * @param out Pointer to location to place the message digest
*/
__device__ void cu_sha1(const void *in, size_t inlen, void *out)
{
   SHA1_CTX ctx;

   cu_sha1_init(&ctx);
   cu_sha1_update(&ctx, in, inlen);
   cu_sha1_final(&ctx, out);
}  /* end cu_sha1() */

/* CUDA kernel function */
__global__ static void kcu_sha1(const void *d_in, size_t *d_inlen,
   size_t max_inlen, void *d_out, int num)
{
   int tid = blockIdx.x * blockDim.x + threadIdx.x;
   if (tid >= num) return;

   uint8_t *in = ((uint8_t *) d_in) + (tid * max_inlen);
   uint8_t *out = ((uint8_t *) d_out) + (tid * SHA1LEN);

   cu_sha1(in, d_inlen[tid], out);
}  /* end kcu_sha1() */

/* CUDA kernel testing function */
void test_kcu_sha1(const void *in, size_t *inlen, size_t max_inlen,
   void *out, int num)
{
   uint8_t *d_in, *d_out;
   size_t *d_inlen;

   cudaMalloc(&d_in, num * max_inlen);
   cudaMalloc(&d_inlen, num * sizeof(size_t));
   cudaMalloc(&d_out, num * SHA1LEN);

   cudaMemcpy(d_in, in, num * max_inlen, cudaMemcpyHostToDevice);
   cudaMemcpy(d_inlen, inlen, num * sizeof(size_t), cudaMemcpyHostToDevice);
   cudaMemset(d_out, 0, num * SHA1LEN);

   kcu_sha1<<<1, num>>>(d_in, d_inlen, max_inlen, d_out, num);

   cudaMemcpy(out, d_out, num * SHA1LEN, cudaMemcpyDeviceToHost);
}  /* end test_kcu_sha1() */

/* end include guard */
#endif
