
/* must be declared before includes */
#ifndef CUDA
   #define CUDA
#endif

#include <string.h>
#include <stdint.h>

#include "_assert.h"
#include "../blake2b.h"

#define NUMVECTORS    7
#define MAXVECTORLEN  81
#define DIGESTLEN     BLAKE2BLEN512

/* Test vectors used in RFC 1321 */
static char rfc_1321_vectors[NUMVECTORS][MAXVECTORLEN] = {
   "",
   "a",
   "abc",
   "message digest",
   "abcdefghijklmnopqrstuvwxyz",
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
   "1234567890123456789012345678901234567890123456789012345678901234"
   "5678901234567890"
};

/* expected results to test vectors */
static uint8_t expect[NUMVECTORS][DIGESTLEN] = {
   {
      0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59, 0x03, 0xc6, 0xc6, 0xfd,
      0x85, 0x25, 0x52, 0xd2, 0x72, 0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58,
      0x47, 0x61, 0x8a, 0x86, 0xe2, 0x17, 0xf7, 0x1f, 0x54, 0x19, 0xd2,
      0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53, 0x13, 0x89, 0x64, 0x44,
      0x93, 0x4e, 0xb0, 0x4b, 0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7,
      0x55, 0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce
   }, {
      0xbf, 0x82, 0x9a, 0xab, 0x39, 0xc6, 0xe3, 0xd4, 0xbc, 0x98, 0xa1,
      0xd6, 0xdc, 0x46, 0x7d, 0x46, 0xec, 0x16, 0xea, 0x28, 0x97, 0x96,
      0x29, 0xd9, 0x15, 0xed, 0x25, 0x74, 0xd5, 0xff, 0xf0, 0xa9, 0x3d,
      0xb5, 0x04, 0x2f, 0xc5, 0xea, 0x3e, 0xaa, 0xe5, 0x72, 0xb0, 0x2b,
      0xee, 0x6e, 0x6a, 0xb1, 0xfa, 0xa4, 0x4b, 0x07, 0xc9, 0xfe, 0x67,
      0x09, 0xb9, 0x98, 0x5f, 0x51, 0xd0, 0x43, 0xc7, 0xa1
   }, {
      0x17, 0xde, 0x51, 0x7e, 0x12, 0x78, 0xd0, 0x0a, 0xc7, 0xa6, 0xbc,
      0xf0, 0x48, 0x88, 0x1a, 0xa9, 0xa9, 0x72, 0xe6, 0xb5, 0xce, 0xf8,
      0x43, 0xd3, 0xc6, 0x1d, 0x3e, 0x25, 0x20, 0x68, 0xa2, 0xf5, 0x26,
      0xc9, 0x99, 0xf4, 0x5c, 0xd9, 0x6b, 0x17, 0x25, 0x09, 0xd0, 0x85,
      0xb5, 0x91, 0x70, 0xe3, 0x88, 0xf8, 0x45, 0x75, 0x0c, 0x81, 0x27,
      0x81, 0xdf, 0x58, 0x2b, 0xe3, 0xfc, 0x4a, 0x19, 0x72
   }, {
      0x8f, 0x6d, 0xe0, 0x60, 0x0e, 0x70, 0x97, 0x90, 0x94, 0xab, 0x83,
      0xaf, 0x16, 0x1c, 0x60, 0xa7, 0xff, 0xf7, 0x72, 0x9e, 0x48, 0x9e,
      0x39, 0x8c, 0xc3, 0xe9, 0x07, 0x4e, 0x3d, 0xd3, 0x3f, 0x0a, 0xc9,
      0x1a, 0x24, 0xda, 0xb3, 0x04, 0x91, 0x26, 0x2c, 0x87, 0x01, 0x95,
      0x34, 0x65, 0x3a, 0x63, 0xb1, 0xcc, 0xbf, 0x0d, 0x5d, 0x46, 0x8e,
      0x83, 0xb1, 0x2b, 0x6f, 0xc7, 0xa3, 0xb6, 0xdd, 0x98
   }, {
      0xca, 0x43, 0x50, 0x5c, 0x2e, 0xa6, 0xe7, 0x08, 0xef, 0x22, 0xdd,
      0x66, 0xac, 0x06, 0x9f, 0xd0, 0x49, 0x7d, 0x11, 0xf8, 0x23, 0x89,
      0x7e, 0x18, 0xed, 0x51, 0x60, 0x95, 0xbd, 0x49, 0x3e, 0x70, 0xf0,
      0xb6, 0x00, 0x8e, 0xcf, 0x70, 0xee, 0x0c, 0x10, 0x83, 0x05, 0x75,
      0xfe, 0x32, 0x62, 0x80, 0x72, 0x1a, 0x7a, 0xf7, 0x07, 0xfd, 0xaa,
      0x11, 0xb0, 0xbc, 0x9f, 0xfb, 0xa5, 0x92, 0x58, 0x45
   }, {
      0x2a, 0x0c, 0xdf, 0x01, 0x3a, 0x4c, 0x81, 0xbf, 0xb2, 0xd4, 0x33,
      0x18, 0xce, 0xb5, 0x08, 0x03, 0x83, 0xed, 0x63, 0x1f, 0x06, 0x77,
      0x93, 0x53, 0x9b, 0x47, 0x8a, 0x7b, 0x7c, 0xa2, 0xd8, 0x46, 0x28,
      0x8d, 0xa4, 0x5f, 0x98, 0x30, 0x02, 0x4c, 0x2c, 0xd7, 0xf2, 0x43,
      0xee, 0xc6, 0x77, 0x13, 0x8e, 0x20, 0x4b, 0x4b, 0xaf, 0x75, 0x1f,
      0x15, 0xbf, 0x49, 0x0e, 0x3d, 0x8e, 0x6d, 0x68, 0x06
   }, { 0 }  /* empty final hash for failure check */
};

int main()
{  /* check 512-bit blake2b(), with key, digest results match expected */
   size_t size_digest, size_ret;
   size_t inlen[NUMVECTORS];
   uint8_t digest[NUMVECTORS][DIGESTLEN];
   int j, ret[NUMVECTORS], keylen[NUMVECTORS];

   /* calc sizes */
   size_digest = sizeof(digest);
   size_ret = sizeof(ret);

   /* init memory (synchronous) */
   memset(ret, 0, size_ret);
   memset(digest, 0, size_digest);

   for (j = 0; j < NUMVECTORS; j++) {
      inlen[j] = keylen[j] = strlen(rfc_1321_vectors[j]);
   }

   /* perform bulk hash */
   test_kcu_blake2b(
      rfc_1321_vectors, inlen, MAXVECTORLEN,
      rfc_1321_vectors, keylen, MAXVECTORLEN,
      digest, DIGESTLEN, ret, NUMVECTORS);

   /* analyze results */
   for (j = 0; j < NUMVECTORS; j++) {
      ASSERT_EQ(ret[j], (j < (NUMVECTORS - 1)) ? 0 : -1);
      ASSERT_CMP(digest[j], expect[j], DIGESTLEN);
   }
}