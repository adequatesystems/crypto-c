/**
 * @file utildev.h
 * @brief Device utilities and includes support.
 * @details Provides utilities and includes for device architectures.
 * | Architecture | Supported |
 * | :----------: | :-------: |
 * | CPU          | Yes       |
 * | CUDA         | Yes       |
 * | OPENCL       | No        |
 * @copyright This file is released into the Public Domain under
 * the Creative Commons Zero v1.0 Universal license.
*/

/* include guard */
#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H


#include <stddef.h>  /* for size_t */
#include <stdint.h>  /* for standard integer types */

/* check for CUDA compilation or definition `-DCUDA` */
#if defined(__NVCC__) || defined(CUDA)
   #pragma comment(lib, "cudart.lib")
   #pragma comment(lib, "nvml.lib")
   #include <cuda_runtime.h>
   #include <nvml.h>

/* end CUDA compilation */
/* #elif defined(__OPENCL_CPP_VERSION__) || defined(OPENCL) */
   /* currently NOT IMPLEMENTED */

/* end OPENCL compilation */
#endif

/* check for CUDA architecture */
#ifdef __CUDA_ARCH__
   #define CRYPTO_ALIGN(x)          __align__(x)
   #define CRYPTO_HOST_DEVICE_FN    __host__ __device__
   #define CRYPTO_BSWAP32(x)        __byte_perm(x, 0, 0x0123);
   /* CUDA is clever enough to automagically recognise these...
   #define CRYPTO_ROTL32(x, n)      __funnelshift_l((x), (x), (n))
   #define CRYPTO_ROTL64(x, n)      ( ((x) << (n)) | ((x) >> (64 - (n))) )
   #define CRYPTO_ROTL32(x, n)      __funnelshift_r((x), (x), (n))
   #define CRYPTO_ROTR64(x, n)      ( ((x) >> (n)) | ((x) << (64 - (n))) )
   #define CRYPTO_XANDX(a, b, c)    ( ((a) & ((b) ^ (c))) ^ (c) )
   #define CRYPTO_XOR3(a, b, c)     ( (a) ^ (b) ^ (c) )
   #define CRYPTO_XOR4(a, b, c, d)  ( (a) ^ (b) ^ (c) ^ (d) ) */

/* end CUDA artchitecture */
/* #elif defined(UNKNOWN_OPENCL_MACRO) */
   /* currently NOT IMPLEMENTED */

/* end OPENCL artchitecture */
#else
   #define CRYPTO_ALIGN(x)   /* no additional declarations */
   #define CRYPTO_HOST_DEVICE_FN    /* no additional declarations */
   #define CRYPTO_BSWAP32(x) \
      ( (rol32(x, 24) & 0xFF00FF00) | (rol32(x, 8) & 0x00FF00FF) )
   /* unnecessary...
   #define CRYPTO_ROTL32(x, n)      ( ((x) << (n)) | ((x) >> (32 - (n))) )
   #define CRYPTO_ROTL64(x, n)      ( ((x) << (n)) | ((x) >> (64 - (n))) )
   #define CRYPTO_ROTR32(x, n)      ( ((x) >> (n)) | ((x) << (32 - (n))) )
   #define CRYPTO_ROTR64(x, n)      ( ((x) >> (n)) | ((x) << (64 - (n))) )
   #define CRYPTO_XANDX(a, b, c)    ( ((a) & ((b) ^ (c))) ^ (c) )
   #define CRYPTO_XOR3(a, b, c)     ( (a) ^ (b) ^ (c) )
   #define CRYPTO_XOR4(a, b, c, d)  ( (a) ^ (b) ^ (c) ^ (d) ) */

/* end CPU compilation */
#endif

/**
 * Declare variable alignment of @a x bytes.
 * Used during the declaration of a variable, indicates to the
 * device compiler that a variable should be aligned to the
 * byte value represented by @a x.
 * <br/>For example, to declare a 32 byte aligned integer constant:
 * @code ALIGN(32) const int aligned_integer = 123; @endcode
 * @param x byte value to align variable to
*/
#define ALIGN(x) CRYPTO_ALIGN(x)

/**
 * Declare function as capable of both "host" and "device" execution.
 * Used during the declaration of a function, indicates to the
 * device compiler that a function is capable of both "host" and
 * "device" execution.<br/>For example:
 * @code HOST_DEVICE_FN int multiarch_function(int x); @endcode
*/
#define HOST_DEVICE_FN  CRYPTO_HOST_DEVICE_FN

/**
 * Swap the byte order of a 32-bit word.
 * @param x 32-bit word to be swapped
 * @returns 32-bit word with swapped byte ordering.
*/
#define bswap32(x)     CRYPTO_BSWAP32(x)

/**
 * Rotate a 32-bit word left by @a n bits.
 * @param x 32-bit word to rotate
 * @param n Number of bits to rotate left by
 * @returns 32-bit word rotated left by @a n bits.
*/
#define rol32(x, n)  ( ((x) << (n)) | ((x) >> (32 - (n))) )

/**
 * Rotate a 64-bit word left by @a n bits.
 * @param x 64-bit word to rotate
 * @param n Number of bits to rotate left by
 * @returns 64-bit word rotated left by @a n bits.
*/
#define rol64(x, n)  ( ((x) << (n)) | ((x) >> (64 - (n))) )

/**
 * Rotate a 32-bit word right by @a n bits.
 * @param x 32-bit word to rotate
 * @param n Number of bits to rotate right by
 * @returns 32-bit word rotated right by @a n bits.
*/
#define ror32(x, n)  ( ((x) >> (n)) | ((x) << (32 - (n))) )

/**
 * Rotate a 64-bit word right by @a n bits.
 * @param x 64-bit word to rotate
 * @param n Number of bits to rotate right by
 * @returns 64-bit word rotated right by @a n bits.
*/
#define ror64(x, n)  ( ((x) >> (n)) | ((x) << (64 - (n))) )

/**
 * Perform an XANDX operation. An XANDX operation is composed
 * of a XOR, an AND and another XOR in the form:
 * @code ( (((a) & ((b) ^ (c))) ^ (c) ) @endcode
 * @param a first parameter
 * @param b second parameter
 * @param c third parameter
 * @returns result of XANDX operation.
*/
#define xandx(a, b, c)  ( ((a) & ((b) ^ (c))) ^ (c) )

/**
 * XOR 3 values together. Performs 2x XOR operations.
 * @param a first parameter
 * @param b second parameter
 * @param c third parameter
 * @returns result of 2x XOR operations.
*/
#define xor3(a, b, c)   ( (a) ^ (b) ^ (c) )

/**
 * XOR 4 values together. Performs 3x XOR operations.
 * @param a first parameter
 * @param b second parameter
 * @param c third parameter
 * @param d fourth parameter
 * @returns result of 3x XOR operations.
*/
#define xor4(a, b, c, d)   ( (a) ^ (b) ^ (c) ^ (d) )

/* device modes */
#define DEV_FAIL  (-1)  /**< Indicates device failure */
#define DEV_NULL  (0)   /**< Indicates initial state of device */
#define DEV_IDLE  (1)   /**< Indicates idling device */
#define DEV_INIT  (2)   /**< Indicates work initialization */
#define DEV_WORK  (3)   /**< Indicates working */

/* end include guard */
#endif
