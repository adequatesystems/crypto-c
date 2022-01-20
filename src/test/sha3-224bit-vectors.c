
#include <stdint.h>
#include "extassert.h"
#include "../sha3.h"

#define NUMVECTORS    7
#define MAXVECTORLEN  81
#define DIGESTLEN     SHA3LEN224

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
      0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb, 0xb7, 0x3b, 0x6e,
      0x15, 0x45, 0x4f, 0x0e, 0xb1, 0xab, 0xd4, 0x59, 0x7f, 0x9a,
      0x1b, 0x07, 0x8e, 0x3f, 0x5b, 0x5a, 0x6b, 0xc7
   }, {
      0x9e, 0x86, 0xff, 0x69, 0x55, 0x7c, 0xa9, 0x5f, 0x40, 0x5f,
      0x08, 0x12, 0x69, 0x68, 0x5b, 0x38, 0xe3, 0xa8, 0x19, 0xb3,
      0x09, 0xee, 0x94, 0x2f, 0x48, 0x2b, 0x6a, 0x8b
   }, {
      0xe6, 0x42, 0x82, 0x4c, 0x3f, 0x8c, 0xf2, 0x4a, 0xd0, 0x92,
      0x34, 0xee, 0x7d, 0x3c, 0x76, 0x6f, 0xc9, 0xa3, 0xa5, 0x16,
      0x8d, 0x0c, 0x94, 0xad, 0x73, 0xb4, 0x6f, 0xdf
   }, {
      0x18, 0x76, 0x8b, 0xb4, 0xc4, 0x8e, 0xb7, 0xfc, 0x88, 0xe5,
      0xdd, 0xb1, 0x7e, 0xfc, 0xf2, 0x96, 0x4a, 0xbd, 0x77, 0x98,
      0xa3, 0x9d, 0x86, 0xa4, 0xb4, 0xa1, 0xe4, 0xc8
   }, {
      0x5c, 0xde, 0xca, 0x81, 0xe1, 0x23, 0xf8, 0x7c, 0xad, 0x96,
      0xb9, 0xcb, 0xa9, 0x99, 0xf1, 0x6f, 0x6d, 0x41, 0x54, 0x96,
      0x08, 0xd4, 0xe0, 0xf4, 0x68, 0x1b, 0x82, 0x39
   }, {
      0xa6, 0x7c, 0x28, 0x9b, 0x82, 0x50, 0xa6, 0xf4, 0x37, 0xa2,
      0x01, 0x37, 0x98, 0x5d, 0x60, 0x55, 0x89, 0xa8, 0xc1, 0x63,
      0xd4, 0x52, 0x61, 0xb1, 0x54, 0x19, 0x55, 0x6e
   }, {
      0x05, 0x26, 0x89, 0x8e, 0x18, 0x58, 0x69, 0xf9, 0x1b, 0x3e,
      0x2a, 0x76, 0xdd, 0x72, 0xa1, 0x5d, 0xc6, 0x94, 0x0a, 0x67,
      0xc8, 0x16, 0x4a, 0x04, 0x4c, 0xd2, 0x5c, 0xc8
   }
};

int main()
{  /* check 224-bit sha3() digest results match expected */
   size_t inlen;
   uint8_t digest[DIGESTLEN];
   int j;

   for (j = 0; j < NUMVECTORS; j++) {
      inlen = strlen(rfc_1321_vectors[j]);
      sha3(rfc_1321_vectors[j], inlen, digest, DIGESTLEN);
      ASSERT_CMP(digest, expect[j], DIGESTLEN);
   }
}
