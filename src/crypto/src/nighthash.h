/*
 * nighthash.h  FPGA-Confuddling Hash Algo
 *
 * Copyright (c) 2019 by Adequate Systems, LLC.  All Rights Reserved.
 * See LICENSE.PDF   **** NO WARRANTY ****
 *
 * Date: 14 June 2019
 * Revision: 1
 *
 * This file is subject to the license as found in LICENSE.PDF
 *
 */

#include "../../hash/src/blake2b.h"
#include "../../hash/src/sha1.h"
#include "../../hash/src/sha256.h"
#include "../../hash/src/sha3.h"
#include "../../hash/src/md2.h"
#include "../../hash/src/md5.h"

#ifndef NIGHTHASH_H
#define NIGHTHASH_H

typedef struct {

   uint32_t digestlen;
   uint32_t algo_type;

   BLAKE2B_CTX blake2b;
   SHA1_CTX sha1;
   SHA256_CTX sha256;
   SHA3_CTX sha3;
   KECCAK_CTX keccak;
   MD2_CTX md2;
   MD5_CTX md5;

} nighthash_ctx_t;

int nighthash_transform_init(nighthash_ctx_t *ctx, byte *algo_type_seed,
                             uint32_t algo_type_seed_length, uint32_t index,
                             uint32_t digestbitlen);
int nighthash_seed_init(nighthash_ctx_t *ctx, byte *algo_type_seed,
                        uint32_t algo_type_seed_length, uint32_t index,
                        uint32_t digestbitlen);
int nighthash_init(nighthash_ctx_t *ctx, uint32_t algo_type, uint32_t digestbitlen);
int nighthash_update(nighthash_ctx_t *ctx, byte *in, uint32_t inlen);
int nighthash_final(nighthash_ctx_t *ctx, byte *out);

#endif
