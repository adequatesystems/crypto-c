/**
 * @private
 * @headerfile sha3.h <sha3.h>
 * @copyright This file is released under The MIT License (MIT).
 * For more information, see the header file...
*/

/* include guard */
#ifndef CRYPTO_SHA3_C
#define CRYPTO_SHA3_C


#include "sha3.h"
#include <string.h>

#define KECCAKFROUNDS   24

/* Keccakf round constant */
ALIGN(32) static const uint64_t keccakf_rndc[24] = {
   0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
   0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
   0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
   0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
   0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
   0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
   0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
   0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

/* SHA3_Keccak permutation */
HOST_DEVICE_FN static void sha3_keccakf(uint64_t st[])
{
	ALIGN(8) uint64_t Ba, Be, Bi, Bo, Bu;
	ALIGN(8) uint64_t Ca, Ce, Ci, Co, Cu;
	ALIGN(8) uint64_t Da, De, Di, Do, Du;
	int r;

	for (r = 0; r < KECCAKFROUNDS; r += 4) {
		/* Unrolled 4 rounds at a time */

		Ca = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
		Ce = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
		Ci = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
		Co = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
		Cu = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];
		Da = Cu ^ rol64(Ce, 1);
		De = Ca ^ rol64(Ci, 1);
		Di = Ce ^ rol64(Co, 1);
		Do = Ci ^ rol64(Cu, 1);
		Du = Co ^ rol64(Ca, 1);

		Ba = (st[0] ^ Da);
		Be = rol64((st[6] ^ De), 44);
		Bi = rol64((st[12] ^ Di), 43);
		Bo = rol64((st[18] ^ Do), 21);
		Bu = rol64((st[24] ^ Du), 14);
		st[0]  = Ba ^ ((~Be) & Bi) ^ keccakf_rndc[r];
		st[6]  = Be ^ ((~Bi) & Bo);
		st[12] = Bi ^ ((~Bo) & Bu);
		st[18] = Bo ^ ((~Bu) & Ba);
		st[24] = Bu ^ ((~Ba) & Be);

		Bi = rol64((st[10] ^ Da), 3);
		Bo = rol64((st[16] ^ De), 45);
		Bu = rol64((st[22] ^ Di), 61);
		Ba = rol64((st[3] ^ Do), 28);
		Be = rol64((st[9] ^ Du), 20);
		st[10] = Ba ^ ((~Be) & Bi);
		st[16] = Be ^ ((~Bi) & Bo);
		st[22] = Bi ^ ((~Bo) & Bu);
		st[3] = Bo ^ ((~Bu) & Ba);
		st[9] = Bu ^ ((~Ba) & Be);

		Bu = rol64((st[20] ^ Da), 18);
		Ba = rol64((st[1] ^ De), 1);
		Be = rol64((st[7] ^ Di), 6);
		Bi = rol64((st[13] ^ Do), 25);
		Bo = rol64((st[19] ^ Du), 8);
		st[20] = Ba ^ ((~Be) & Bi);
		st[1] = Be ^ ((~Bi) & Bo);
		st[7] = Bi ^ ((~Bo) & Bu);
		st[13] = Bo ^ ((~Bu) & Ba);
		st[19] = Bu ^ ((~Ba) & Be);

		Be = rol64((st[5] ^ Da), 36);
		Bi = rol64((st[11] ^ De), 10);
		Bo = rol64((st[17] ^ Di), 15);
		Bu = rol64((st[23] ^ Do), 56);
		Ba = rol64((st[4] ^ Du), 27);
		st[5] = Ba ^ ((~Be) & Bi);
		st[11] = Be ^ ((~Bi) & Bo);
		st[17] = Bi ^ ((~Bo) & Bu);
		st[23] = Bo ^ ((~Bu) & Ba);
		st[4] = Bu ^ ((~Ba) & Be);

		Bo = rol64((st[15] ^ Da), 41);
		Bu = rol64((st[21] ^ De), 2);
		Ba = rol64((st[2] ^ Di), 62);
		Be = rol64((st[8] ^ Do), 55);
		Bi = rol64((st[14] ^ Du), 39);
		st[15] = Ba ^ ((~Be) & Bi);
		st[21] = Be ^ ((~Bi) & Bo);
		st[2] = Bi ^ ((~Bo) & Bu);
		st[8] = Bo ^ ((~Bu) & Ba);
		st[14] = Bu ^ ((~Ba) & Be);

		Ca = st[0] ^ st[10] ^ st[20] ^ st[5] ^ st[15];
		Ce = st[6] ^ st[16] ^ st[1] ^ st[11] ^ st[21];
		Ci = st[12] ^ st[22] ^ st[7] ^ st[17] ^ st[2];
		Co = st[18] ^ st[3] ^ st[13] ^ st[23] ^ st[8];
		Cu = st[24] ^ st[9] ^ st[19] ^ st[4] ^ st[14];
		Da = Cu ^ rol64(Ce, 1);
		De = Ca ^ rol64(Ci, 1);
		Di = Ce ^ rol64(Co, 1);
		Do = Ci ^ rol64(Cu, 1);
		Du = Co ^ rol64(Ca, 1);

		Ba = (st[0] ^ Da);
		Be = rol64((st[16] ^ De), 44);
		Bi = rol64((st[7] ^ Di), 43);
		Bo = rol64((st[23] ^ Do), 21);
		Bu = rol64((st[14] ^ Du), 14);
		st[0] = Ba ^ ((~Be) & Bi) ^ keccakf_rndc[r + 1];
		st[16] = Be ^ ((~Bi) & Bo);
		st[7] = Bi ^ ((~Bo) & Bu);
		st[23] = Bo ^ ((~Bu) & Ba);
		st[14] = Bu ^ ((~Ba) & Be);

		Bi = rol64((st[20] ^ Da), 3);
		Bo = rol64((st[11] ^ De), 45);
		Bu = rol64((st[2] ^ Di), 61);
		Ba = rol64((st[18] ^ Do), 28);
		Be = rol64((st[9] ^ Du), 20);
		st[20] = Ba ^ ((~Be) & Bi);
		st[11] = Be ^ ((~Bi) & Bo);
		st[2] = Bi ^ ((~Bo) & Bu);
		st[18] = Bo ^ ((~Bu) & Ba);
		st[9] = Bu ^ ((~Ba) & Be);

		Bu = rol64((st[15] ^ Da), 18);
		Ba = rol64((st[6] ^ De), 1);
		Be = rol64((st[22] ^ Di), 6);
		Bi = rol64((st[13] ^ Do), 25);
		Bo = rol64((st[4] ^ Du), 8);
		st[15] = Ba ^ ((~Be) & Bi);
		st[6] = Be ^ ((~Bi) & Bo);
		st[22] = Bi ^ ((~Bo) & Bu);
		st[13] = Bo ^ ((~Bu) & Ba);
		st[4] = Bu ^ ((~Ba) & Be);

		Be = rol64((st[10] ^ Da), 36);
		Bi = rol64((st[1] ^ De), 10);
		Bo = rol64((st[17] ^ Di), 15);
		Bu = rol64((st[8] ^ Do), 56);
		Ba = rol64((st[24] ^ Du), 27);
		st[10] = Ba ^ ((~Be) & Bi);
		st[1] = Be ^ ((~Bi) & Bo);
		st[17] = Bi ^ ((~Bo) & Bu);
		st[8] = Bo ^ ((~Bu) & Ba);
		st[24] = Bu ^ ((~Ba) & Be);

		Bo = rol64((st[5] ^ Da), 41);
		Bu = rol64((st[21] ^ De), 2);
		Ba = rol64((st[12] ^ Di), 62);
		Be = rol64((st[3] ^ Do), 55);
		Bi = rol64((st[19] ^ Du), 39);
		st[5] = Ba ^ ((~Be) & Bi);
		st[21] = Be ^ ((~Bi) & Bo);
		st[12] = Bi ^ ((~Bo) & Bu);
		st[3] = Bo ^ ((~Bu) & Ba);
		st[19] = Bu ^ ((~Ba) & Be);

		Ca = st[0] ^ st[20] ^ st[15] ^ st[10] ^ st[5];
		Ce = st[16] ^ st[11] ^ st[6] ^ st[1] ^ st[21];
		Ci = st[7] ^ st[2] ^ st[22] ^ st[17] ^ st[12];
		Co = st[23] ^ st[18] ^ st[13] ^ st[8] ^ st[3];
		Cu = st[14] ^ st[9] ^ st[4] ^ st[24] ^ st[19];
		Da = Cu ^ rol64(Ce, 1);
		De = Ca ^ rol64(Ci, 1);
		Di = Ce ^ rol64(Co, 1);
		Do = Ci ^ rol64(Cu, 1);
		Du = Co ^ rol64(Ca, 1);

		Ba = (st[0] ^ Da);
		Be = rol64((st[11] ^ De), 44);
		Bi = rol64((st[22] ^ Di), 43);
		Bo = rol64((st[8] ^ Do), 21);
		Bu = rol64((st[19] ^ Du), 14);
		st[0] = Ba ^ ((~Be) & Bi) ^ keccakf_rndc[r + 2];
		st[11] = Be ^ ((~Bi) & Bo);
		st[22] = Bi ^ ((~Bo) & Bu);
		st[8] = Bo ^ ((~Bu) & Ba);
		st[19] = Bu ^ ((~Ba) & Be);

		Bi = rol64((st[15] ^ Da), 3);
		Bo = rol64((st[1] ^ De), 45);
		Bu = rol64((st[12] ^ Di), 61);
		Ba = rol64((st[23] ^ Do), 28);
		Be = rol64((st[9] ^ Du), 20);
		st[15] = Ba ^ ((~Be) & Bi);
		st[1] = Be ^ ((~Bi) & Bo);
		st[12] = Bi ^ ((~Bo) & Bu);
		st[23] = Bo ^ ((~Bu) & Ba);
		st[9] = Bu ^ ((~Ba) & Be);

		Bu = rol64((st[5] ^ Da), 18);
		Ba = rol64((st[16] ^ De), 1);
		Be = rol64((st[2] ^ Di), 6);
		Bi = rol64((st[13] ^ Do), 25);
		Bo = rol64((st[24] ^ Du), 8);
		st[5] = Ba ^ ((~Be) & Bi);
		st[16] = Be ^ ((~Bi) & Bo);
		st[2] = Bi ^ ((~Bo) & Bu);
		st[13] = Bo ^ ((~Bu) & Ba);
		st[24] = Bu ^ ((~Ba) & Be);

		Be = rol64((st[20] ^ Da), 36);
		Bi = rol64((st[6] ^ De), 10);
		Bo = rol64((st[17] ^ Di), 15);
		Bu = rol64((st[3] ^ Do), 56);
		Ba = rol64((st[14] ^ Du), 27);
		st[20] = Ba ^ ((~Be) & Bi);
		st[6] = Be ^ ((~Bi) & Bo);
		st[17] = Bi ^ ((~Bo) & Bu);
		st[3] = Bo ^ ((~Bu) & Ba);
		st[14] = Bu ^ ((~Ba) & Be);

		Bo = rol64((st[10] ^ Da), 41);
		Bu = rol64((st[21] ^ De), 2);
		Ba = rol64((st[7] ^ Di), 62);
		Be = rol64((st[18] ^ Do), 55);
		Bi = rol64((st[4] ^ Du), 39);
		st[10] = Ba ^ ((~Be) & Bi);
		st[21] = Be ^ ((~Bi) & Bo);
		st[7] = Bi ^ ((~Bo) & Bu);
		st[18] = Bo ^ ((~Bu) & Ba);
		st[4] = Bu ^ ((~Ba) & Be);

		Ca = st[0] ^ st[15] ^ st[5] ^ st[20] ^ st[10];
		Ce = st[11] ^ st[1] ^ st[16] ^ st[6] ^ st[21];
		Ci = st[22] ^ st[12] ^ st[2] ^ st[17] ^ st[7];
		Co = st[8] ^ st[23] ^ st[13] ^ st[3] ^ st[18];
		Cu = st[19] ^ st[9] ^ st[24] ^ st[14] ^ st[4];
		Da = Cu ^ rol64(Ce, 1);
		De = Ca ^ rol64(Ci, 1);
		Di = Ce ^ rol64(Co, 1);
		Do = Ci ^ rol64(Cu, 1);
		Du = Co ^ rol64(Ca, 1);

		Ba = (st[0] ^ Da);
		Be = rol64((st[1] ^ De), 44);
		Bi = rol64((st[2] ^ Di), 43);
		Bo = rol64((st[3] ^ Do), 21);
		Bu = rol64((st[4] ^ Du), 14);
		st[0] = Ba ^ ((~Be) & Bi) ^ keccakf_rndc[r + 3];
		st[1] = Be ^ ((~Bi) & Bo);
		st[2] = Bi ^ ((~Bo) & Bu);
		st[3] = Bo ^ ((~Bu) & Ba);
		st[4] = Bu ^ ((~Ba) & Be);

		Bi = rol64((st[5] ^ Da), 3);
		Bo = rol64((st[6] ^ De), 45);
		Bu = rol64((st[7] ^ Di), 61);
		Ba = rol64((st[8] ^ Do), 28);
		Be = rol64((st[9] ^ Du), 20);
		st[5] = Ba ^ ((~Be) & Bi);
		st[6] = Be ^ ((~Bi) & Bo);
		st[7] = Bi ^ ((~Bo) & Bu);
		st[8] = Bo ^ ((~Bu) & Ba);
		st[9] = Bu ^ ((~Ba) & Be);

		Bu = rol64((st[10] ^ Da), 18);
		Ba = rol64((st[11] ^ De), 1);
		Be = rol64((st[12] ^ Di), 6);
		Bi = rol64((st[13] ^ Do), 25);
		Bo = rol64((st[14] ^ Du), 8);
		st[10] = Ba ^ ((~Be) & Bi);
		st[11] = Be ^ ((~Bi) & Bo);
		st[12] = Bi ^ ((~Bo) & Bu);
		st[13] = Bo ^ ((~Bu) & Ba);
		st[14] = Bu ^ ((~Ba) & Be);

		Be = rol64((st[15] ^ Da), 36);
		Bi = rol64((st[16] ^ De), 10);
		Bo = rol64((st[17] ^ Di), 15);
		Bu = rol64((st[18] ^ Do), 56);
		Ba = rol64((st[19] ^ Du), 27);
		st[15] = Ba ^ ((~Be) & Bi);
		st[16] = Be ^ ((~Bi) & Bo);
		st[17] = Bi ^ ((~Bo) & Bu);
		st[18] = Bo ^ ((~Bu) & Ba);
		st[19] = Bu ^ ((~Ba) & Be);

		Bo = rol64((st[20] ^ Da), 41);
		Bu = rol64((st[21] ^ De), 2);
		Ba = rol64((st[22] ^ Di), 62);
		Be = rol64((st[23] ^ Do), 55);
		Bi = rol64((st[24] ^ Du), 39);
		st[20] = Ba ^ ((~Be) & Bi);
		st[21] = Be ^ ((~Bi) & Bo);
		st[22] = Bi ^ ((~Bo) & Bu);
		st[23] = Bo ^ ((~Bu) & Ba);
		st[24] = Bu ^ ((~Ba) & Be);
	}
}  /* end sha3_keccakf() */

/* Initialize the hashing context `ctx` */
HOST_DEVICE_FN void sha3_init(SHA3_CTX *ctx, int outlen)
{
   memset(ctx->st.b, 0, 200);
   ctx->outlen = (uint32_t) outlen;
   ctx->rsiz = 200 - (ctx->outlen << 1);
   ctx->pt = 0;
}

/* Add `inlen` bytes from `in` into the hash */
HOST_DEVICE_FN void sha3_update(SHA3_CTX *ctx, const void *in, size_t inlen)
{
   size_t i;

   for (i = 0; i < inlen; i++) {
      ctx->st.b[ctx->pt++] ^= ((const uint8_t *) in)[i];
      if (ctx->pt == ctx->rsiz) {
         sha3_keccakf(ctx->st.q);
         ctx->pt = 0;
      }
   }
}

/* Generate the message digest and place in `out` */
HOST_DEVICE_FN void sha3_final(SHA3_CTX *ctx, void *out)
{
   ctx->st.b[ctx->pt] ^= 0x06;
   ctx->st.b[ctx->rsiz - 1] ^= 0x80;
   sha3_keccakf(ctx->st.q);

   /* copy digest to out */
   memcpy(out, ctx->st.q, ctx->outlen);
}
HOST_DEVICE_FN void keccak_final(SHA3_CTX *ctx, void *out)
{
   /* This next step essentially converts the sha3_final() step
    * `c->st.b[c->pt] ^= 0x06;`  (to)  `c->st.b[c->pt] ^= 0x01;`
    * as per the original Keccak implementation. */
   ctx->st.b[ctx->pt] ^= 0x07;
   sha3_final(ctx, out);
}

/* Convenient all-in-one SHA3 computation */
HOST_DEVICE_FN void sha3(const void *in, size_t inlen, void *out, int outlen)
{
   SHA3_CTX sha3;

   sha3_init(&sha3, outlen);
   sha3_update(&sha3, in, inlen);
   sha3_final(&sha3, out);
}

/* Convenient all-in-one Keccak computation */
HOST_DEVICE_FN void keccak(const void *in, size_t inlen, void *out, int outlen)
{
   KECCAK_CTX keccak;

   keccak_init(&keccak, outlen);
   keccak_update(&keccak, in, inlen);
   keccak_final(&keccak, out);
}


#endif  /* end _CRYPTO_SHA3_C_ */
