/**
 * @private
 * @headerfile base58.h <base58.h>
 * @copyright This file is released into the Public Domain under
 * the Creative Commons Zero v1.0 Universal license.
*/

/* include guard */
#ifndef CRYPTO_BASE58_C
#define CRYPTO_BASE58_C


#include "base58.h"

/* system support */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static const char base58_alphabet[] =
   "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const char base58_map[] = {
   -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
   -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
   -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
   -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
   -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
   22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
   -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
   47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
};

/**
 * Encode a buffer into base58 format.
 * @param in Pointer to the buffer to encode
 * @param inlen Length of the buffer to encode
 * @param out Pointer to the buffer to store the encoded string
 * @returns When out is left NULL, the function returns the length of
 * the expected output data. When out is provided, the function returns
 * 0 on success, or -1 on failure. In the event of an error, errno is
 * set to indicate the error.
 */
int base58_encode(const void *in, size_t inlen, char *out)
{
   const unsigned char *bin = in;
   unsigned char *buffer;
   size_t idx, zeros;
   int carry, high, low, size;

   /* check input */
   if (in == NULL || inlen == 0) {
      errno = EINVAL;
      return (-1);
   }

   /* count leading zeros for internal buffer size calc */
   for (zeros = 0; zeros < inlen && !bin[zeros]; zeros++);
   low = size = ((((int) inlen - zeros) * 138) / 100) + 1;
   buffer = calloc(size, sizeof(unsigned char));
   if (buffer == NULL) return (-1);

   /* convert input to base58 buffer */
   for (idx = zeros, high = size - 1; idx < inlen; high = low, idx++) {
      for (low = size - 1, carry = bin[idx]; (low > high) || carry; low--) {
         if (low < 0) break; /* prevent overflow operations */
         carry += 256 * buffer[low];
         buffer[low] = carry % 58;
         carry /= 58;
      }
   }
   low++;

   /* return required output buffer size, if out is NULL */
   if (out == NULL) {
      free(buffer);
      return (int) zeros + size - low;
   }

   /* low is adjusted AFTER calculating required output buffer length */
   //low++;

   /* convert base58 buffer to alphabet -- leading base58(0)='1' */
   memset(out, '1', zeros);
   while (low < size) out[zeros++] = base58_alphabet[buffer[low++]];
   out[zeros] = '\0';
   free(buffer);

   return 0;
}  /* end base58_encode() */

/**
 * Decode a base58 encoded string into a buffer.
 * @param in Pointer to the null-terminated base58 encoded string
 * @param out Pointer to the buffer to store the decoded data
 * @return When out is left NULL, the function returns the length of
 * the expected output data. When out is provided, the function returns
 * 0 on success, or -1 on failure. In the event of an error, errno is
 * set to indicate the error.
 */
int base58_decode(const char* in, void *out)
{
   unsigned char *buffer;
   size_t idx, inlen, zeros;
   int carry, high, low, size;

   /* check input */
   buffer = NULL;
   if (in == NULL) goto EINVAL_CLEANUP;
   inlen = strlen(in);
   if (inlen == 0) goto EINVAL_CLEANUP;

   /* count leading '1' for internal buffer size calc */
   for (zeros = 0; zeros < inlen && in[zeros] == '1'; zeros++);
   low = size = (((inlen - zeros) * 733) / 1000) + 1;
   buffer = calloc(size, sizeof(unsigned char));
   if (buffer == NULL) return (-1);

   /* convert input to binary buffer */
   for (idx = zeros, high = size - 1; idx < inlen; high = low, idx++) {
      /* check (invalid) characters -- high bit or negative mapping */
      if (in[idx] & 0x80) goto EINVAL_CLEANUP;
      carry = base58_map[(unsigned char) in[idx]];
      if (carry == (-1)) goto EINVAL_CLEANUP;
      for (low = size - 1; (low > high) || carry; low--) {
         if (low < 0) break; /* prevent overflow operations */
         carry += 58 * buffer[low];
         buffer[low] = carry & 0xff;
         carry >>= 8;
      }
   }

   /* low is adjusted BEFORE calculating required output buffer length */
   low++;

   /* return required output buffer size, if out is NULL */
   if (out == NULL) {
      free(buffer);
      return zeros + size - low;
   }

   /* convert base58 buffer to alphabet -- leading base58(0)='1' */
   memset(out, 0, zeros);
   memcpy(((unsigned char *) out) + zeros, buffer + low, size - low);
   free(buffer);

   return 0;

EINVAL_CLEANUP:
   if (buffer) free(buffer);
   errno = EINVAL;
   return (-1);
}  /* end base58_decode() */

/* end include guard */
#endif
