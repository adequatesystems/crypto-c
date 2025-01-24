
#include "base58.c"

#include "_vectors.h"
#include <assert.h>
#include <stdio.h>

/* base58 results of vectors input */
static char *rfc_1321_results[NUMVECTORS] = {
   "",   /* skipped */
   "2g",
   "ZiCa",
   "hDdfg5c7zoqQzkxAtHq",
   "3yxU3u1igY8WkgtjK92fbJQCd4BZiiT1v25f",
   "4tJBETbod9RcGRhGUXbdjU3t4jtbW8ySYiRVRn2XmqPVNZyexrFZ3S1mfsisKv2S2vgtSqPYk8WQy35D9dbbW",
   "Y6QKeB2p6J9Ba9RaCMwdaEHccu7K6LMzTPXhwTSPGT9Ngv98JwjUAD2mbu8CbVjFR1hgXc15KNE6WRbEb6G4tRuHXekt8JdD4iSLubv5e4WRd"
};

void test_encode_invalid_input(char *out)
{
   errno = 0;
   assert(base58_encode(NULL, 0, out) == (-1));
   assert(errno == EINVAL);
}

void test_encode_invalid_input_length(char *out)
{
   errno = 0;
   assert(base58_encode(out, 0, out) == (-1));
   assert(errno == EINVAL);
}

void test_encode_output_length(const char *in, size_t inlen, int expect)
{
/*
   printf("test_encode_return_count(\"%s\", %zu, %d)\n", in, inlen, expect);
*/
   assert(base58_encode(in, inlen, NULL) == expect);
}

void test_encode_output(const char *in, size_t inlen, const char *expect)
{
   char output[128] = {0};
/*
   base58_encode(in, inlen, output);
   printf("test_encode_output(\"%s\", %zu, \"%s\"): \"%s\"\n",
      in, inlen, expect, output);
*/
   assert(base58_encode(in, inlen, output) == 0);
   assert(strcmp(output, expect) == 0);
}

void test_decode_invalid_input(char *out)
{
   errno = 0;
   assert(base58_decode(NULL, out) == (-1));
   assert(errno == EINVAL);
}

void test_decode_invalid_input_length(char *out)
{
   errno = 0;
   assert(base58_decode("", out) == (-1));
   assert(errno == EINVAL);
}

void test_decode_invalid_char_bit(char *out)
{
   errno = 0;
   assert(base58_decode((char[2]){-1}, out) == (-1));
   assert(errno == EINVAL);
}

void test_decode_invalid_char_map(char *out)
{
   errno = 0;
   assert(base58_decode("+++", out) == (-1));
   assert(errno == EINVAL);
}

void test_decode_output_length(const char *in, int expect)
{
/*
   printf("test_decode_return_count(\"%s\", %zu, %d)\n", in, inlen, expect);
*/
   assert(base58_decode(in, NULL) == expect);
}

void test_decode_output(const char *in, const char *expect)
{
   char output[128] = {0};
/*
   base58_decode(in, output);
   printf("test_decode_output(\"%s\", \"%s\"): \"%s\"\n",
      in, expect, output);
*/
   assert(base58_decode(in, output) == 0);
   assert(strcmp(output, expect) == 0);
}

int main()
{
   char buffer[128];
   const char *expect;
   const char *in;
   size_t inlen;
   int idx;

   /* test failure modes */
   test_encode_invalid_input(buffer);
   test_encode_invalid_input_length(buffer);
   test_decode_invalid_input(buffer);
   test_decode_invalid_char_bit(buffer);
   test_decode_invalid_char_map(buffer);

   /* skip first vector "" -- invalid */
   for (idx = 1; idx < NUMVECTORS; idx++) {
      in = rfc_1321_vectors[idx];
      inlen = strlen(in);
      expect = rfc_1321_results[idx];
      /* NOTE: +1 for null termination */
      test_encode_output_length(in, inlen, strlen(expect));
      test_encode_output(in, inlen, expect);

      expect = rfc_1321_vectors[idx];
      test_decode_output_length(rfc_1321_results[idx], strlen(expect));
      test_decode_output(rfc_1321_results[idx], expect);
   }
}
