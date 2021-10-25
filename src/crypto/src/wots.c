/**
 * wots.c - WOTS+ Public address, Signature, and Verification
 *
 * Copyright (c) 2018-2021 Adequate Systems, LLC. All Rights Reserved.
 * For more information, please refer to ../LICENSE
 *
 * Date: 25 May 2018
 * Revised: 17 September 2021
 *
 * Our implementation of WOTS+ is derived from the XMSS reference
 * implementation written by Andreas Huelsing and Joost Rijneveld
 * of the Crypto Forum Research Group:
 * "XMSS: Extended Hash-Based Signatures"
 *   https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/draft-irtf-cfrg-xmss-hash-based-signatures-11
 *
 * Update: 12/11/2018 - the above RFC was moved from Draft status
 * to published RFC, and can now be found here:
 * "XMSS: eXtended Merkle Signature Scheme"
 *   https://datatracker.ietf.org/doc/rfc8391/
 *
 * The reference implementation is permanently available at
 *   https://github.com/joostrijneveld/xmss-reference
 * under the CC0 1.0 Universal Public Domain Dedication.
 * For more information, please refer to
 *   http://creativecommons.org/publicdomain/zero/1.0/
 *
*/

#ifndef _SIGN_WOTS_C_
#define _SIGN_WOTS_C_


#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "wots.h"
#include "sha256.h"

void set_key_and_mask(uint32_t addr[8], uint32_t key_and_mask)
{
    addr[7] = key_and_mask;
}

void set_chain_addr(uint32_t addr[8], uint32_t chain)
{
    addr[5] = chain;
}

void set_hash_addr(uint32_t addr[8], uint32_t hash)
{
    addr[6] = hash;
}

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(uint8_t *out, unsigned int outlen, unsigned long in)
{
    int i;

    /* Iterate over out in decreasing order, for big-endianness. */
    for (i = outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}


void addr_to_bytes(uint8_t *bytes, const uint32_t addr[8])
{
    int i;
    for (i = 0; i < 8; i++) {
        ull_to_bytes(bytes + i*4, 4, addr[i]);
    }
}

/*
 * Computes PRF(key, in), for a key of PARAMSN bytes, and a 32-byte input.
 */
int prf(uint8_t *out, const uint8_t in[32], const uint8_t *key)
{
    uint8_t buf[2 * PARAMSN + 32];

    ull_to_bytes(buf, PARAMSN, XMSS_HASH_PADDING_PRF);
    memcpy(buf + PARAMSN, key, PARAMSN);
    memcpy(buf + (2*PARAMSN), in, 32);
    core_hash(out, buf, (2*PARAMSN) + 32);
    return 0;
}


int thash_f(uint8_t *out, const uint8_t *in,
            const uint8_t *pub_seed, uint32_t addr[8])
{
    uint8_t buf[3 * PARAMSN];
    uint8_t bitmask[PARAMSN];
    uint8_t addr_as_bytes[32];
    unsigned int i;

    /* Set the function padding. */
    ull_to_bytes(buf, PARAMSN, XMSS_HASH_PADDING_F);

    /* Generate the n-byte key. */
    set_key_and_mask(addr, 0);
    addr_to_bytes(addr_as_bytes, addr);
    prf(buf + PARAMSN, addr_as_bytes, pub_seed);

    /* Generate the n-byte mask. */
    set_key_and_mask(addr, 1);
    addr_to_bytes(addr_as_bytes, addr);
    prf(bitmask, addr_as_bytes, pub_seed);

    for (i = 0; i < PARAMSN; i++) {
        buf[2*PARAMSN + i] = in[i] ^ bitmask[i];
    }
    core_hash(out, buf, 3 * PARAMSN);
    return 0;
}

/**
 * Helper method for pseudorandom key generation.
 * Expands an n-byte array into a len*n byte array using the `prf` function.
 */
static void expand_seed(uint8_t *outseeds, const uint8_t *inseed)
{
    uint32_t i;
    uint8_t ctr[32];

    for (i = 0; i < WOTSLEN; i++) {
        ull_to_bytes(ctr, 32, i);
        prf(outseeds + i*PARAMSN, ctr, inseed);
    }
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static void gen_chain(uint8_t *out, const uint8_t *in,
                      unsigned int start, unsigned int steps,
                      const uint8_t *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, PARAMSN);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start+steps) && i < WOTSW; i++) {
        set_hash_addr(addr, i);
        thash_f(out, out, pub_seed, addr);
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(int *output, const int out_len, const uint8_t *input)
{
    int in = 0;
    int out = 0;
    uint8_t total;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= WOTSLOGW;
        output[out] = (total >> bits) & (WOTSW - 1);
        out++;
    }
}

/* Computes the WOTS+ checksum over a message (in base_w). */
static void wots_checksum(int *csum_base_w, const int *msg_base_w)
{
    int csum = 0;
    uint8_t csum_bytes[(WOTSLEN2 * WOTSLOGW + 7) / 8];
    unsigned int i;

    /* Compute checksum. */
    for (i = 0; i < WOTSLEN1; i++) {
        csum += WOTSW - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << (8 - ((WOTSLEN2 * WOTSLOGW) % 8));
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w(csum_base_w, WOTSLEN2, csum_bytes);
}

/* Takes a message and derives the matching chain lengths. */
static void chain_lengths(int *lengths, const uint8_t *msg)
{
    base_w(lengths, WOTSLEN1, msg);
    wots_checksum(lengths + WOTSLEN1, lengths);
}

/**
 * WOTS key generation. Takes a 32 byte seed for the private key, expands it to
 * a full WOTS private key and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this WOTS key pair.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pkgen(uint8_t *pk, const uint8_t *seed,
                const uint8_t *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(pk, seed);

    for (i = 0; i < WOTSLEN; i++) {
        set_chain_addr(addr, i);
        gen_chain(pk + i * PARAMSN, pk + i * PARAMSN,
                  0, WOTSW - 1, pub_seed, addr);
    }
}

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
void wots_sign(uint8_t *sig, const uint8_t *msg,
               const uint8_t *seed, const uint8_t *pub_seed,
               uint32_t addr[8])
{
    int lengths[WOTSLEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(sig, seed);

    for (i = 0; i < WOTSLEN; i++) {
        set_chain_addr(addr, i);
        gen_chain(sig + i * PARAMSN, sig + i * PARAMSN,
                  0, lengths[i], pub_seed, addr);
    }
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(uint8_t *pk,
                      const uint8_t *sig, const uint8_t *msg,
                      const uint8_t *pub_seed, uint32_t addr[8])
{
    int lengths[WOTSLEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    for (i = 0; i < WOTSLEN; i++) {
        set_chain_addr(addr, i);
        gen_chain(pk + i * PARAMSN, sig + i * PARAMSN,
                  lengths[i], WOTSW - 1 - lengths[i], pub_seed, addr);
    }
}


#endif  /* end _SIGN_WOTS_C_ */
