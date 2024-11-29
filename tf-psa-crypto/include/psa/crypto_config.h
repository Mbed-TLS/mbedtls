/**
 * \file psa/crypto_config.h
 * \brief PSA crypto configuration options (set of defines)
 *
 */
/**
 * This file determines which cryptographic mechanisms are enabled
 * through the PSA Cryptography API (\c psa_xxx() functions).
 *
 * To enable a cryptographic mechanism, uncomment the definition of
 * the corresponding \c PSA_WANT_xxx preprocessor symbol.
 * To disable a cryptographic mechanism, comment out the definition of
 * the corresponding \c PSA_WANT_xxx preprocessor symbol.
 * The names of cryptographic mechanisms correspond to values
 * defined in psa/crypto_values.h, with the prefix \c PSA_WANT_ instead
 * of \c PSA_.
 *
 * Note that many cryptographic mechanisms involve two symbols: one for
 * the key type (\c PSA_WANT_KEY_TYPE_xxx) and one for the algorithm
 * (\c PSA_WANT_ALG_xxx). Mechanisms with additional parameters may involve
 * additional symbols.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_CONFIG_H
#define PSA_CRYPTO_CONFIG_H

/**
 * \name SECTION: SECTION Cryptographic mechanism selection (PSA API)
 *
 * This section sets PSA API settings.
 * \{
 */

/*
 * CBC-MAC is not yet supported via the PSA API in Mbed TLS.
 */
//#define PSA_WANT_ALG_CBC_MAC                    1
#define PSA_WANT_ALG_CBC_NO_PADDING             1
#define PSA_WANT_ALG_CBC_PKCS7                  1
#define PSA_WANT_ALG_CCM                        1
#define PSA_WANT_ALG_CCM_STAR_NO_TAG            1
#define PSA_WANT_ALG_CMAC                       1
#define PSA_WANT_ALG_CFB                        1
#define PSA_WANT_ALG_CHACHA20_POLY1305          1
#define PSA_WANT_ALG_CTR                        1
#define PSA_WANT_ALG_DETERMINISTIC_ECDSA        1
#define PSA_WANT_ALG_ECB_NO_PADDING             1
#define PSA_WANT_ALG_ECDH                       1
#define PSA_WANT_ALG_FFDH                       1
#define PSA_WANT_ALG_ECDSA                      1
#define PSA_WANT_ALG_JPAKE                      1
#define PSA_WANT_ALG_GCM                        1
#define PSA_WANT_ALG_HKDF                       1
#define PSA_WANT_ALG_HKDF_EXTRACT               1
#define PSA_WANT_ALG_HKDF_EXPAND                1
#define PSA_WANT_ALG_HMAC                       1
#define PSA_WANT_ALG_MD5                        1
#define PSA_WANT_ALG_OFB                        1
#define PSA_WANT_ALG_PBKDF2_HMAC                1
#define PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128    1
#define PSA_WANT_ALG_RIPEMD160                  1
#define PSA_WANT_ALG_RSA_OAEP                   1
#define PSA_WANT_ALG_RSA_PKCS1V15_CRYPT         1
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN          1
#define PSA_WANT_ALG_RSA_PSS                    1
#define PSA_WANT_ALG_SHA_1                      1
#define PSA_WANT_ALG_SHA_224                    1
#define PSA_WANT_ALG_SHA_256                    1
#define PSA_WANT_ALG_SHA_384                    1
#define PSA_WANT_ALG_SHA_512                    1
#define PSA_WANT_ALG_SHA3_224                   1
#define PSA_WANT_ALG_SHA3_256                   1
#define PSA_WANT_ALG_SHA3_384                   1
#define PSA_WANT_ALG_SHA3_512                   1
#define PSA_WANT_ALG_STREAM_CIPHER              1
#define PSA_WANT_ALG_TLS12_PRF                  1
#define PSA_WANT_ALG_TLS12_PSK_TO_MS            1
#define PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS       1

/* XTS is not yet supported via the PSA API in Mbed TLS.
 * Note: when adding support, also adjust include/mbedtls/config_psa.h */
//#define PSA_WANT_ALG_XTS                        1

#define PSA_WANT_ECC_BRAINPOOL_P_R1_256         1
#define PSA_WANT_ECC_BRAINPOOL_P_R1_384         1
#define PSA_WANT_ECC_BRAINPOOL_P_R1_512         1
#define PSA_WANT_ECC_MONTGOMERY_255             1
#define PSA_WANT_ECC_MONTGOMERY_448             1
#define PSA_WANT_ECC_SECP_K1_192                1
/*
 * SECP224K1 is buggy via the PSA API in Mbed TLS
 * (https://github.com/Mbed-TLS/mbedtls/issues/3541). Thus, do not enable it by
 * default.
 */
//#define PSA_WANT_ECC_SECP_K1_224                1
#define PSA_WANT_ECC_SECP_K1_256                1
#define PSA_WANT_ECC_SECP_R1_192                1
#define PSA_WANT_ECC_SECP_R1_224                1
/* For secp256r1, consider enabling #MBEDTLS_PSA_P256M_DRIVER_ENABLED
 * (see the description in mbedtls/mbedtls_config.h for details). */
#define PSA_WANT_ECC_SECP_R1_256                1
#define PSA_WANT_ECC_SECP_R1_384                1
#define PSA_WANT_ECC_SECP_R1_521                1

#define PSA_WANT_DH_RFC7919_2048                1
#define PSA_WANT_DH_RFC7919_3072                1
#define PSA_WANT_DH_RFC7919_4096                1
#define PSA_WANT_DH_RFC7919_6144                1
#define PSA_WANT_DH_RFC7919_8192                1

#define PSA_WANT_KEY_TYPE_DERIVE                1
#define PSA_WANT_KEY_TYPE_PASSWORD              1
#define PSA_WANT_KEY_TYPE_PASSWORD_HASH         1
#define PSA_WANT_KEY_TYPE_HMAC                  1
#define PSA_WANT_KEY_TYPE_AES                   1
#define PSA_WANT_KEY_TYPE_ARIA                  1
#define PSA_WANT_KEY_TYPE_CAMELLIA              1
#define PSA_WANT_KEY_TYPE_CHACHA20              1
#define PSA_WANT_KEY_TYPE_DES                   1
//#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR          1 /* Deprecated */
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_DH_PUBLIC_KEY         1
#define PSA_WANT_KEY_TYPE_RAW_DATA              1
//#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR          1 /* Deprecated */
#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY        1

/*
 * The following symbols extend and deprecate the legacy
 * PSA_WANT_KEY_TYPE_xxx_KEY_PAIR ones. They include the usage of that key in
 * the name's suffix. "_USE" is the most generic and it can be used to describe
 * a generic suport, whereas other ones add more features on top of that and
 * they are more specific.
 */
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC      1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE   1

#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC      1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE 1
//#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_DERIVE   1 /* Not supported */

#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_BASIC       1
#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_IMPORT    1
#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_EXPORT    1
#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_GENERATE  1
//#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_DERIVE    1 /* Not supported */
/** \} name SECTION Cryptographic mechanism selection (PSA API) */

/**
 * \name SECTION: Platform abstraction layer
 *
 * This section sets platform specific settings.
 * \{
 */

/**
 * \def MBEDTLS_MEMORY_BUFFER_ALLOC_C
 *
 * Enable the buffer allocator implementation that makes use of a (stack)
 * based buffer to 'allocate' dynamic memory. (replaces calloc() and free()
 * calls)
 *
 * Module:  library/memory_buffer_alloc.c
 *
 * Requires: MBEDTLS_PLATFORM_C
 *           MBEDTLS_PLATFORM_MEMORY (to use it within Mbed TLS)
 *
 * Enable this module to enable the buffer memory allocator.
 */
//#define MBEDTLS_MEMORY_BUFFER_ALLOC_C

/**
 * \def MBEDTLS_FS_IO
 *
 * Enable functions that use the filesystem.
 */
#define MBEDTLS_FS_IO

/**
 * \def MBEDTLS_HAVE_TIME
 *
 * System has time.h and time().
 * The time does not need to be correct, only time differences are used,
 * by contrast with MBEDTLS_HAVE_TIME_DATE
 *
 * Defining MBEDTLS_HAVE_TIME allows you to specify MBEDTLS_PLATFORM_TIME_ALT,
 * MBEDTLS_PLATFORM_TIME_MACRO, MBEDTLS_PLATFORM_TIME_TYPE_MACRO and
 * MBEDTLS_PLATFORM_STD_TIME.
 *
 * Comment if your system does not support time functions.
 *
 * \note If MBEDTLS_TIMING_C is set - to enable the semi-portable timing
 *       interface - timing.c will include time.h on suitable platforms
 *       regardless of the setting of MBEDTLS_HAVE_TIME, unless
 *       MBEDTLS_TIMING_ALT is used. See timing.c for more information.
 */
#define MBEDTLS_HAVE_TIME

/**
 * \def MBEDTLS_HAVE_TIME_DATE
 *
 * System has time.h, time(), and an implementation for
 * mbedtls_platform_gmtime_r() (see below).
 * The time needs to be correct (not necessarily very accurate, but at least
 * the date should be correct). This is used to verify the validity period of
 * X.509 certificates.
 *
 * Comment if your system does not have a correct clock.
 *
 * \note mbedtls_platform_gmtime_r() is an abstraction in platform_util.h that
 * behaves similarly to the gmtime_r() function from the C standard. Refer to
 * the documentation for mbedtls_platform_gmtime_r() for more information.
 *
 * \note It is possible to configure an implementation for
 * mbedtls_platform_gmtime_r() at compile-time by using the macro
 * MBEDTLS_PLATFORM_GMTIME_R_ALT.
 */
#define MBEDTLS_HAVE_TIME_DATE

/**
 * \def MBEDTLS_MEMORY_DEBUG
 *
 * Enable debugging of buffer allocator memory issues. Automatically prints
 * (to stderr) all (fatal) messages on memory allocation issues. Enables
 * function for 'debug output' of allocated memory.
 *
 * Requires: MBEDTLS_MEMORY_BUFFER_ALLOC_C
 *
 * Uncomment this macro to let the buffer allocator print out error messages.
 */
//#define MBEDTLS_MEMORY_DEBUG

/**
 * \def MBEDTLS_MEMORY_BACKTRACE
 *
 * Include backtrace information with each allocated block.
 *
 * Requires: MBEDTLS_MEMORY_BUFFER_ALLOC_C
 *           GLIBC-compatible backtrace() and backtrace_symbols() support
 *
 * Uncomment this macro to include backtrace information
 */
//#define MBEDTLS_MEMORY_BACKTRACE

/**
 * \def MBEDTLS_PLATFORM_C
 *
 * Enable the platform abstraction layer that allows you to re-assign
 * functions like calloc(), free(), snprintf(), printf(), fprintf(), exit().
 *
 * Enabling MBEDTLS_PLATFORM_C enables to use of MBEDTLS_PLATFORM_XXX_ALT
 * or MBEDTLS_PLATFORM_XXX_MACRO directives, allowing the functions mentioned
 * above to be specified at runtime or compile time respectively.
 *
 * \note This abstraction layer must be enabled on Windows (including MSYS2)
 * as other modules rely on it for a fixed snprintf implementation.
 *
 * Module:  library/platform.c
 * Caller:  Most other .c files
 *
 * This module enables abstraction of common (libc) functions.
 */
#define MBEDTLS_PLATFORM_C

/**
 * \def MBEDTLS_PLATFORM_EXIT_ALT
 *
 * MBEDTLS_PLATFORM_XXX_ALT: Uncomment a macro to let Mbed TLS support the
 * function in the platform abstraction layer.
 *
 * Example: In case you uncomment MBEDTLS_PLATFORM_PRINTF_ALT, Mbed TLS will
 * provide a function "mbedtls_platform_set_printf()" that allows you to set an
 * alternative printf function pointer.
 *
 * All these define require MBEDTLS_PLATFORM_C to be defined!
 *
 * \note MBEDTLS_PLATFORM_SNPRINTF_ALT is required on Windows;
 * it will be enabled automatically by check_config.h
 *
 * \warning MBEDTLS_PLATFORM_XXX_ALT cannot be defined at the same time as
 * MBEDTLS_PLATFORM_XXX_MACRO!
 *
 * Requires: MBEDTLS_PLATFORM_TIME_ALT requires MBEDTLS_HAVE_TIME
 *
 * Uncomment a macro to enable alternate implementation of specific base
 * platform function
 */
//#define MBEDTLS_PLATFORM_SETBUF_ALT
//#define MBEDTLS_PLATFORM_EXIT_ALT
//#define MBEDTLS_PLATFORM_TIME_ALT
//#define MBEDTLS_PLATFORM_FPRINTF_ALT
//#define MBEDTLS_PLATFORM_PRINTF_ALT
//#define MBEDTLS_PLATFORM_SNPRINTF_ALT
//#define MBEDTLS_PLATFORM_VSNPRINTF_ALT
//#define MBEDTLS_PLATFORM_NV_SEED_ALT
//#define MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT
//#define MBEDTLS_PLATFORM_MS_TIME_ALT

/**
 * Uncomment the macro to let Mbed TLS use your alternate implementation of
 * mbedtls_platform_gmtime_r(). This replaces the default implementation in
 * platform_util.c.
 *
 * gmtime() is not a thread-safe function as defined in the C standard. The
 * library will try to use safer implementations of this function, such as
 * gmtime_r() when available. However, if Mbed TLS cannot identify the target
 * system, the implementation of mbedtls_platform_gmtime_r() will default to
 * using the standard gmtime(). In this case, calls from the library to
 * gmtime() will be guarded by the global mutex mbedtls_threading_gmtime_mutex
 * if MBEDTLS_THREADING_C is enabled. We recommend that calls from outside the
 * library are also guarded with this mutex to avoid race conditions. However,
 * if the macro MBEDTLS_PLATFORM_GMTIME_R_ALT is defined, Mbed TLS will
 * unconditionally use the implementation for mbedtls_platform_gmtime_r()
 * supplied at compile time.
 */
//#define MBEDTLS_PLATFORM_GMTIME_R_ALT

/**
 * \def MBEDTLS_PLATFORM_MEMORY
 *
 * Enable the memory allocation layer.
 *
 * By default Mbed TLS uses the system-provided calloc() and free().
 * This allows different allocators (self-implemented or provided) to be
 * provided to the platform abstraction layer.
 *
 * Enabling #MBEDTLS_PLATFORM_MEMORY without the
 * MBEDTLS_PLATFORM_{FREE,CALLOC}_MACROs will provide
 * "mbedtls_platform_set_calloc_free()" allowing you to set an alternative calloc() and
 * free() function pointer at runtime.
 *
 * Enabling #MBEDTLS_PLATFORM_MEMORY and specifying
 * MBEDTLS_PLATFORM_{CALLOC,FREE}_MACROs will allow you to specify the
 * alternate function at compile time.
 *
 * An overview of how the value of mbedtls_calloc is determined:
 *
 * - if !MBEDTLS_PLATFORM_MEMORY
 *     - mbedtls_calloc = calloc
 * - if MBEDTLS_PLATFORM_MEMORY
 *     - if (MBEDTLS_PLATFORM_CALLOC_MACRO && MBEDTLS_PLATFORM_FREE_MACRO):
 *         - mbedtls_calloc = MBEDTLS_PLATFORM_CALLOC_MACRO
 *     - if !(MBEDTLS_PLATFORM_CALLOC_MACRO && MBEDTLS_PLATFORM_FREE_MACRO):
 *         - Dynamic setup via mbedtls_platform_set_calloc_free is now possible with a default value MBEDTLS_PLATFORM_STD_CALLOC.
 *         - How is MBEDTLS_PLATFORM_STD_CALLOC handled?
 *         - if MBEDTLS_PLATFORM_NO_STD_FUNCTIONS:
 *             - MBEDTLS_PLATFORM_STD_CALLOC is not set to anything;
 *             - MBEDTLS_PLATFORM_STD_MEM_HDR can be included if present;
 *         - if !MBEDTLS_PLATFORM_NO_STD_FUNCTIONS:
 *             - if MBEDTLS_PLATFORM_STD_CALLOC is present:
 *                 - User-defined MBEDTLS_PLATFORM_STD_CALLOC is respected;
 *             - if !MBEDTLS_PLATFORM_STD_CALLOC:
 *                 - MBEDTLS_PLATFORM_STD_CALLOC = calloc
 *
 *         - At this point the presence of MBEDTLS_PLATFORM_STD_CALLOC is checked.
 *         - if !MBEDTLS_PLATFORM_STD_CALLOC
 *             - MBEDTLS_PLATFORM_STD_CALLOC = uninitialized_calloc
 *
 *         - mbedtls_calloc = MBEDTLS_PLATFORM_STD_CALLOC.
 *
 * Defining MBEDTLS_PLATFORM_CALLOC_MACRO and #MBEDTLS_PLATFORM_STD_CALLOC at the same time is not possible.
 * MBEDTLS_PLATFORM_CALLOC_MACRO and MBEDTLS_PLATFORM_FREE_MACRO must both be defined or undefined at the same time.
 * #MBEDTLS_PLATFORM_STD_CALLOC and #MBEDTLS_PLATFORM_STD_FREE do not have to be defined at the same time, as, if they are used,
 * dynamic setup of these functions is possible. See the tree above to see how are they handled in all cases.
 * An uninitialized #MBEDTLS_PLATFORM_STD_CALLOC always fails, returning a null pointer.
 * An uninitialized #MBEDTLS_PLATFORM_STD_FREE does not do anything.
 *
 * Requires: MBEDTLS_PLATFORM_C
 *
 * Enable this layer to allow use of alternative memory allocators.
 */
//#define MBEDTLS_PLATFORM_MEMORY

/**
 * \def MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
 *
 * Do not assign standard functions in the platform layer (e.g. calloc() to
 * MBEDTLS_PLATFORM_STD_CALLOC and printf() to MBEDTLS_PLATFORM_STD_PRINTF)
 *
 * This makes sure there are no linking errors on platforms that do not support
 * these functions. You will HAVE to provide alternatives, either at runtime
 * via the platform_set_xxx() functions or at compile time by setting
 * the MBEDTLS_PLATFORM_STD_XXX defines, or enabling a
 * MBEDTLS_PLATFORM_XXX_MACRO.
 *
 * Requires: MBEDTLS_PLATFORM_C
 *
 * Uncomment to prevent default assignment of standard functions in the
 * platform layer.
 */
//#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS

/**
 * Uncomment the macro to let Mbed TLS use your alternate implementation of
 * mbedtls_platform_zeroize(), to wipe sensitive data in memory. This replaces
 * the default implementation in platform_util.c.
 *
 * By default, the library uses a system function such as memset_s()
 * (optional feature of C11), explicit_bzero() (BSD and compatible), or
 * SecureZeroMemory (Windows). If no such function is detected, the library
 * falls back to a plain C implementation. Compilers are technically
 * permitted to optimize this implementation out, meaning that the memory is
 * not actually wiped. The library tries to prevent that, but the C language
 * makes it impossible to guarantee that the memory will always be wiped.
 *
 * If your platform provides a guaranteed method to wipe memory which
 * `platform_util.c` does not detect, define this macro to the name of
 * a function that takes two arguments, a `void *` pointer and a length,
 * and wipes that many bytes starting at the specified address. For example,
 * if your platform has explicit_bzero() but `platform_util.c` does not
 * detect its presence, define `MBEDTLS_PLATFORM_ZEROIZE_ALT` to be
 * `explicit_bzero` to use that function as mbedtls_platform_zeroize().
 */
//#define MBEDTLS_PLATFORM_ZEROIZE_ALT

/**
 * \def MBEDTLS_THREADING_ALT
 *
 * Provide your own alternate threading implementation.
 *
 * Requires: MBEDTLS_THREADING_C
 *
 * Uncomment this to allow your own alternate threading implementation.
 */
//#define MBEDTLS_THREADING_ALT

/**
 * \def MBEDTLS_THREADING_PTHREAD
 *
 * Enable the pthread wrapper layer for the threading layer.
 *
 * Requires: MBEDTLS_THREADING_C
 *
 * Uncomment this to enable pthread mutexes.
 */
//#define MBEDTLS_THREADING_PTHREAD

/**
 * \def MBEDTLS_THREADING_C
 *
 * Enable the threading abstraction layer.
 * By default Mbed TLS assumes it is used in a non-threaded environment or that
 * contexts are not shared between threads. If you do intend to use contexts
 * between threads, you will need to enable this layer to prevent race
 * conditions. See also our Knowledge Base article about threading:
 * https://mbed-tls.readthedocs.io/en/latest/kb/development/thread-safety-and-multi-threading
 *
 * Module:  library/threading.c
 *
 * This allows different threading implementations (self-implemented or
 * provided).
 *
 * You will have to enable either MBEDTLS_THREADING_ALT or
 * MBEDTLS_THREADING_PTHREAD.
 *
 * Enable this layer to allow use of mutexes within Mbed TLS
 */
//#define MBEDTLS_THREADING_C

/* Memory buffer allocator options */
//#define MBEDTLS_MEMORY_ALIGN_MULTIPLE      4 /**< Align on multiples of this value */

/* To use the following function macros, MBEDTLS_PLATFORM_C must be enabled. */
/* MBEDTLS_PLATFORM_XXX_MACRO and MBEDTLS_PLATFORM_XXX_ALT cannot both be defined */
//#define MBEDTLS_PLATFORM_CALLOC_MACRO        calloc /**< Default allocator macro to use, can be undefined. See MBEDTLS_PLATFORM_STD_CALLOC for requirements. */
//#define MBEDTLS_PLATFORM_EXIT_MACRO            exit /**< Default exit macro to use, can be undefined */
//#define MBEDTLS_PLATFORM_FREE_MACRO            free /**< Default free macro to use, can be undefined. See MBEDTLS_PLATFORM_STD_FREE for requirements. */
//#define MBEDTLS_PLATFORM_FPRINTF_MACRO      fprintf /**< Default fprintf macro to use, can be undefined */
//#define MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO   int64_t //#define MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO   int64_t /**< Default milliseconds time macro to use, can be undefined. MBEDTLS_HAVE_TIME must be enabled. It must be signed, and at least 64 bits. If it is changed from the default, MBEDTLS_PRINTF_MS_TIME must be updated to match.*/
//#define MBEDTLS_PLATFORM_NV_SEED_READ_MACRO   mbedtls_platform_std_nv_seed_read /**< Default nv_seed_read function to use, can be undefined */
//#define MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO  mbedtls_platform_std_nv_seed_write /**< Default nv_seed_write function to use, can be undefined */
//#define MBEDTLS_PLATFORM_PRINTF_MACRO        printf /**< Default printf macro to use, can be undefined */
//#define MBEDTLS_PLATFORM_SETBUF_MACRO      setbuf /**< Default setbuf macro to use, can be undefined */
/* Note: your snprintf must correctly zero-terminate the buffer! */
//#define MBEDTLS_PLATFORM_SNPRINTF_MACRO    snprintf /**< Default snprintf macro to use, can be undefined */

/** \def MBEDTLS_PLATFORM_STD_CALLOC
 *
 * Default allocator to use, can be undefined.
 * It must initialize the allocated buffer memory to zeroes.
 * The size of the buffer is the product of the two parameters.
 * The calloc function returns either a null pointer or a pointer to the allocated space.
 * If the product is 0, the function may either return NULL or a valid pointer to an array of size 0 which is a valid input to the deallocation function.
 * An uninitialized #MBEDTLS_PLATFORM_STD_CALLOC always fails, returning a null pointer.
 * See the description of #MBEDTLS_PLATFORM_MEMORY for more details.
 * The corresponding deallocation function is #MBEDTLS_PLATFORM_STD_FREE.
 */
//#define MBEDTLS_PLATFORM_STD_CALLOC        calloc

//#define MBEDTLS_PLATFORM_STD_EXIT            exit /**< Default exit to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_EXIT_FAILURE       1 /**< Default exit value to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_EXIT_SUCCESS       0 /**< Default exit value to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_FPRINTF      fprintf /**< Default fprintf to use, can be undefined */

/** \def MBEDTLS_PLATFORM_STD_FREE
 *
 * Default free to use, can be undefined.
 * NULL is a valid parameter, and the function must do nothing.
 * A non-null parameter will always be a pointer previously returned by #MBEDTLS_PLATFORM_STD_CALLOC and not yet freed.
 * An uninitialized #MBEDTLS_PLATFORM_STD_FREE does not do anything.
 * See the description of #MBEDTLS_PLATFORM_MEMORY for more details (same principles as for MBEDTLS_PLATFORM_STD_CALLOC apply).
 */
//#define MBEDTLS_PLATFORM_STD_FREE            free

//#define MBEDTLS_PLATFORM_STD_MEM_HDR   <stdlib.h> /**< Header to include if MBEDTLS_PLATFORM_NO_STD_FUNCTIONS is defined. Don't define if no header is needed. */
//#define MBEDTLS_PLATFORM_STD_NV_SEED_FILE  "seedfile" /**< Seed file to read/write with default implementation */
//#define MBEDTLS_PLATFORM_STD_NV_SEED_READ   mbedtls_platform_std_nv_seed_read /**< Default nv_seed_read function to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_NV_SEED_WRITE  mbedtls_platform_std_nv_seed_write /**< Default nv_seed_write function to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_PRINTF        printf /**< Default printf to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_SETBUF      setbuf /**< Default setbuf to use, can be undefined */
/* Note: your snprintf must correctly zero-terminate the buffer! */
//#define MBEDTLS_PLATFORM_STD_SNPRINTF    snprintf /**< Default snprintf to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_TIME            time /**< Default time to use, can be undefined. MBEDTLS_HAVE_TIME must be enabled */
//#define MBEDTLS_PLATFORM_TIME_MACRO            time /**< Default time macro to use, can be undefined. MBEDTLS_HAVE_TIME must be enabled */
//#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO       time_t /**< Default time macro to use, can be undefined. MBEDTLS_HAVE_TIME must be enabled */
//#define MBEDTLS_PLATFORM_VSNPRINTF_MACRO    vsnprintf /**< Default vsnprintf macro to use, can be undefined */
//#define MBEDTLS_PRINTF_MS_TIME    PRId64 /**< Default fmt for printf. That's avoid compiler warning if mbedtls_ms_time_t is redefined */

/** \} name SECTION: Platform abstraction layer */

/**
 * \name SECTION: General and test configuration options
 *
 * This section sets test specific settings.
 * \{
 */

/**
 * \def MBEDTLS_CHECK_RETURN_WARNING
 *
 * If this macro is defined, emit a compile-time warning if application code
 * calls a function without checking its return value, but the return value
 * should generally be checked in portable applications.
 *
 * This is only supported on platforms where #MBEDTLS_CHECK_RETURN is
 * implemented. Otherwise this option has no effect.
 *
 * Uncomment to get warnings on using fallible functions without checking
 * their return value.
 *
 * \note  This feature is a work in progress.
 *        Warnings will be added to more functions in the future.
 *
 * \note  A few functions are considered critical, and ignoring the return
 *        value of these functions will trigger a warning even if this
 *        macro is not defined. To completely disable return value check
 *        warnings, define #MBEDTLS_CHECK_RETURN with an empty expansion.
 */
//#define MBEDTLS_CHECK_RETURN_WARNING

/**
 * \def MBEDTLS_DEPRECATED_WARNING
 *
 * Mark deprecated functions and features so that they generate a warning if
 * used. Functionality deprecated in one version will usually be removed in the
 * next version. You can enable this to help you prepare the transition to a
 * new major version by making sure your code is not using this functionality.
 *
 * This only works with GCC and Clang. With other compilers, you may want to
 * use MBEDTLS_DEPRECATED_REMOVED
 *
 * Uncomment to get warnings on using deprecated functions and features.
 */
//#define MBEDTLS_DEPRECATED_WARNING

/**
 * \def MBEDTLS_DEPRECATED_REMOVED
 *
 * Remove deprecated functions and features so that they generate an error if
 * used. Functionality deprecated in one version will usually be removed in the
 * next version. You can enable this to help you prepare the transition to a
 * new major version by making sure your code is not using this functionality.
 *
 * Uncomment to get errors on using deprecated functions and features.
 */
//#define MBEDTLS_DEPRECATED_REMOVED

/** \def MBEDTLS_CHECK_RETURN
 *
 * This macro is used at the beginning of the declaration of a function
 * to indicate that its return value should be checked. It should
 * instruct the compiler to emit a warning or an error if the function
 * is called without checking its return value.
 *
 * There is a default implementation for popular compilers in platform_util.h.
 * You can override the default implementation by defining your own here.
 *
 * If the implementation here is empty, this will effectively disable the
 * checking of functions' return values.
 */
//#define MBEDTLS_CHECK_RETURN __attribute__((__warn_unused_result__))

/** \def MBEDTLS_IGNORE_RETURN
 *
 * This macro requires one argument, which should be a C function call.
 * If that function call would cause a #MBEDTLS_CHECK_RETURN warning, this
 * warning is suppressed.
 */
//#define MBEDTLS_IGNORE_RETURN( result ) ((void) !(result))

/**
 * \def TF_PSA_CRYPTO_CONFIG_FILE
 *
 * If defined, this is a header which will be included instead of
 * `"psa/crypto_config.h"`.
 * This header file specifies which cryptographic mechanisms are available
 * through the PSA API.
 *
 * This macro is expanded after an <tt>\#include</tt> directive. This is a popular but
 * non-standard feature of the C language, so this feature is only available
 * with compilers that perform macro expansion on an <tt>\#include</tt> line.
 *
 * The value of this symbol is typically a path in double quotes, either
 * absolute or relative to a directory on the include search path.
 */
//#define TF_PSA_CRYPTO_CONFIG_FILE "psa/crypto_config.h"

/**
 * \def TF_PSA_CRYPTO_USER_CONFIG_FILE
 *
 * If defined, this is a header which will be included after
 * `"psa/crypto_config.h"` or #TF_PSA_CRYPTO_CONFIG_FILE.
 * This allows you to modify the default configuration, including the ability
 * to undefine options that are enabled by default.
 *
 * This macro is expanded after an <tt>\#include</tt> directive. This is a popular but
 * non-standard feature of the C language, so this feature is only available
 * with compilers that perform macro expansion on an <tt>\#include</tt> line.
 *
 * The value of this symbol is typically a path in double quotes, either
 * absolute or relative to a directory on the include search path.
 */
//#define TF_PSA_CRYPTO_USER_CONFIG_FILE "/dev/null"

/**
 * \def MBEDTLS_SELF_TEST
 *
 * Enable the checkup functions (*_self_test).
 */
#define MBEDTLS_SELF_TEST

/**
 * \def MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN
 *
 * Enable testing of the constant-flow nature of some sensitive functions with
 * clang's MemorySanitizer. This causes some existing tests to also test
 * this non-functional property of the code under test.
 *
 * This setting requires compiling with clang -fsanitize=memory. The test
 * suites can then be run normally.
 *
 * \warning This macro is only used for extended testing; it is not considered
 * part of the library's API, so it may change or disappear at any time.
 *
 * Uncomment to enable testing of the constant-flow nature of selected code.
 */
//#define MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN

/**
 * \def MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND
 *
 * Enable testing of the constant-flow nature of some sensitive functions with
 * valgrind's memcheck tool. This causes some existing tests to also test
 * this non-functional property of the code under test.
 *
 * This setting requires valgrind headers for building, and is only useful for
 * testing if the tests suites are run with valgrind's memcheck. This can be
 * done for an individual test suite with 'valgrind ./test_suite_xxx', or when
 * using CMake, this can be done for all test suites with 'make memcheck'.
 *
 * \warning This macro is only used for extended testing; it is not considered
 * part of the library's API, so it may change or disappear at any time.
 *
 * Uncomment to enable testing of the constant-flow nature of selected code.
 */
//#define MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND

/**
 * \def MBEDTLS_TEST_HOOKS
 *
 * Enable features for invasive testing such as introspection functions and
 * hooks for fault injection. This enables additional unit tests.
 *
 * Merely enabling this feature should not change the behavior of the product.
 * It only adds new code, and new branching points where the default behavior
 * is the same as when this feature is disabled.
 * However, this feature increases the attack surface: there is an added
 * risk of vulnerabilities, and more gadgets that can make exploits easier.
 * Therefore this feature must never be enabled in production.
 *
 * See `docs/architecture/testing/mbed-crypto-invasive-testing.md` for more
 * information.
 *
 * Uncomment to enable invasive tests.
 */
//#define MBEDTLS_TEST_HOOKS

/** \} name SECTION: General and test configuration options */

/**
 * \name SECTION: Cryptographic mechanism selection (extended API)
 *
 * This section sets cryptographic mechanism settings.
 * \{
 */

/**
 * \def MBEDTLS_LMS_C
 *
 * Enable the LMS stateful-hash asymmetric signature algorithm.
 *
 * Module:  library/lms.c
 * Caller:
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C
 *
 * Uncomment to enable the LMS verification algorithm and public key operations.
 */
#define MBEDTLS_LMS_C

/**
 * \def MBEDTLS_LMS_PRIVATE
 *
 * Enable LMS private-key operations and signing code. Functions enabled by this
 * option are experimental, and should not be used in production.
 *
 * Requires: MBEDTLS_LMS_C
 *
 * Uncomment to enable the LMS signature algorithm and private key operations.
 */
//#define MBEDTLS_LMS_PRIVATE

/**
 * \def MBEDTLS_MD_C
 *
 * Enable the generic layer for message digest (hashing) and HMAC.
 *
 * Requires: one of: MBEDTLS_MD5_C, MBEDTLS_RIPEMD160_C, MBEDTLS_SHA1_C,
 *                   MBEDTLS_SHA224_C, MBEDTLS_SHA256_C, MBEDTLS_SHA384_C,
 *                   MBEDTLS_SHA512_C, or MBEDTLS_PSA_CRYPTO_C with at least
 *                   one hash.
 * Module:  library/md.c
 * Caller:  library/constant_time.c
 *          library/ecdsa.c
 *          library/ecjpake.c
 *          library/hkdf.c
 *          library/hmac_drbg.c
 *          library/pk.c
 *          library/pkcs5.c
 *          library/pkcs12.c
 *          library/psa_crypto_ecp.c
 *          library/psa_crypto_rsa.c
 *          library/rsa.c
 *          library/ssl_cookie.c
 *          library/ssl_msg.c
 *          library/ssl_tls.c
 *          library/x509.c
 *          library/x509_crt.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 *
 * Uncomment to enable generic message digest wrappers.
 */
#define MBEDTLS_MD_C

/**
 * \def MBEDTLS_NIST_KW_C
 *
 * Enable the Key Wrapping mode for 128-bit block ciphers,
 * as defined in NIST SP 800-38F. Only KW and KWP modes
 * are supported. At the moment, only AES is approved by NIST.
 *
 * Module:  library/nist_kw.c
 *
 * Requires: MBEDTLS_AES_C and MBEDTLS_CIPHER_C
 */
#define MBEDTLS_NIST_KW_C

/**
 * \def MBEDTLS_PK_C
 *
 * Enable the generic public (asymmetric) key layer.
 *
 * Module:  library/pk.c
 * Caller:  library/psa_crypto_rsa.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *          library/x509.c
 *
 * Requires: MBEDTLS_MD_C, MBEDTLS_RSA_C or MBEDTLS_ECP_C
 *
 * Uncomment to enable generic public key wrappers.
 */
#define MBEDTLS_PK_C

/**
 * \def MBEDTLS_PKCS5_C
 *
 * Enable PKCS#5 functions.
 *
 * Module:  library/pkcs5.c
 *
 * Auto-enables: MBEDTLS_MD_C
 *
 * \warning If using a hash that is only provided by PSA drivers, you must
 * call psa_crypto_init() before doing any PKCS5 operations.
 *
 * This module adds support for the PKCS#5 functions.
 */
#define MBEDTLS_PKCS5_C

/**
 * \def MBEDTLS_PKCS12_C
 *
 * Enable PKCS#12 PBE functions.
 * Adds algorithms for parsing PKCS#8 encrypted private keys
 *
 * Module:  library/pkcs12.c
 * Caller:  library/pkparse.c
 *
 * Requires: MBEDTLS_ASN1_PARSE_C and either MBEDTLS_MD_C or
 *           MBEDTLS_PSA_CRYPTO_C.
 *
 * \warning If using a hash that is only provided by PSA drivers, you must
 * call psa_crypto_init() before doing any PKCS12 operations.
 *
 * This module enables PKCS#12 functions.
 */
#define MBEDTLS_PKCS12_C

/**
 * \def MBEDTLS_PK_PARSE_C
 *
 * Enable the generic public (asymmetric) key parser.
 *
 * Module:  library/pkparse.c
 * Caller:  library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: MBEDTLS_ASN1_PARSE_C, MBEDTLS_OID_C, MBEDTLS_PK_C
 *
 * Uncomment to enable generic public key parse functions.
 */
#define MBEDTLS_PK_PARSE_C

/**
 * \def MBEDTLS_PK_PARSE_EC_EXTENDED
 *
 * Enhance support for reading EC keys using variants of SEC1 not allowed by
 * RFC 5915 and RFC 5480.
 *
 * Currently this means parsing the SpecifiedECDomain choice of EC
 * parameters (only known groups are supported, not arbitrary domains, to
 * avoid validation issues).
 *
 * Disable if you only need to support RFC 5915 + 5480 key formats.
 */
#define MBEDTLS_PK_PARSE_EC_EXTENDED

/**
 * \def MBEDTLS_PK_PARSE_EC_COMPRESSED
 *
 * Enable the support for parsing public keys of type Short Weierstrass
 * (MBEDTLS_ECP_DP_SECP_XXX and MBEDTLS_ECP_DP_BP_XXX) which are using the
 * compressed point format. This parsing is done through ECP module's functions.
 *
 * \note As explained in the description of MBEDTLS_ECP_PF_COMPRESSED (in ecp.h)
 *       the only unsupported curves are MBEDTLS_ECP_DP_SECP224R1 and
 *       MBEDTLS_ECP_DP_SECP224K1.
 */
#define MBEDTLS_PK_PARSE_EC_COMPRESSED

/**
 * \def MBEDTLS_PK_RSA_ALT_SUPPORT
 *
 * Support external private RSA keys (eg from a HSM) in the PK layer.
 *
 * Comment this macro to disable support for external private RSA keys.
 */
#define MBEDTLS_PK_RSA_ALT_SUPPORT

/**
 * \def MBEDTLS_PK_WRITE_C
 *
 * Enable the generic public (asymmetric) key writer.
 *
 * Module:  library/pkwrite.c
 * Caller:  library/x509write.c
 *
 * Requires: MBEDTLS_ASN1_WRITE_C, MBEDTLS_OID_C, MBEDTLS_PK_C
 *
 * Uncomment to enable generic public key write functions.
 */
#define MBEDTLS_PK_WRITE_C

/* CTR_DRBG options */
//#define MBEDTLS_CTR_DRBG_ENTROPY_LEN               48 /**< Amount of entropy used per seed by default (48 with SHA-512, 32 with SHA-256) */
//#define MBEDTLS_CTR_DRBG_MAX_INPUT                256 /**< Maximum number of additional input bytes */
//#define MBEDTLS_CTR_DRBG_MAX_REQUEST             1024 /**< Maximum number of requested bytes per call */
//#define MBEDTLS_CTR_DRBG_MAX_SEED_INPUT           384 /**< Maximum size of (re)seed buffer */
//#define MBEDTLS_CTR_DRBG_RESEED_INTERVAL        10000 /**< Interval before reseed is performed by default */

/* HMAC_DRBG options */
//#define MBEDTLS_HMAC_DRBG_MAX_INPUT           256 /**< Maximum number of additional input bytes */
//#define MBEDTLS_HMAC_DRBG_MAX_REQUEST        1024 /**< Maximum number of requested bytes per call */
//#define MBEDTLS_HMAC_DRBG_MAX_SEED_INPUT      384 /**< Maximum size of (re)seed buffer */
//#define MBEDTLS_HMAC_DRBG_RESEED_INTERVAL   10000 /**< Interval before reseed is performed by default */

/* PSA options */
/**
 * Use HMAC_DRBG with the specified hash algorithm for HMAC_DRBG for the
 * PSA crypto subsystem.
 *
 * If this option is unset, the library chooses a hash (currently between
 * #MBEDTLS_MD_SHA512 and #MBEDTLS_MD_SHA256) based on availability and
 * unspecified heuristics.
 *
 * \note The PSA crypto subsystem uses the first available mechanism amongst
 *       the following:
 *       - #MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG if enabled;
 *       - Entropy from #MBEDTLS_ENTROPY_C plus CTR_DRBG with AES
 *         if #MBEDTLS_CTR_DRBG_C is enabled;
 *       - Entropy from #MBEDTLS_ENTROPY_C plus HMAC_DRBG.
 *
 *       A future version may reevaluate the prioritization of DRBG mechanisms.
 */
//#define MBEDTLS_PSA_HMAC_DRBG_MD_TYPE MBEDTLS_MD_SHA256

/** \} name SECTION: Cryptographic mechanism selection (extended API) */

/**
 * \name SECTION: Data format support
 *
 * This section sets data-format specific settings.
 * \{
 */

/**
 * \def MBEDTLS_ASN1_PARSE_C
 *
 * Enable the generic ASN1 parser.
 *
 * Module:  library/asn1.c
 * Caller:  library/x509.c
 *          library/dhm.c
 *          library/pkcs12.c
 *          library/pkcs5.c
 *          library/pkparse.c
 */
#define MBEDTLS_ASN1_PARSE_C

/**
 * \def MBEDTLS_ASN1_WRITE_C
 *
 * Enable the generic ASN1 writer.
 *
 * Module:  library/asn1write.c
 * Caller:  library/ecdsa.c
 *          library/pkwrite.c
 *          library/x509_create.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 */
#define MBEDTLS_ASN1_WRITE_C

/**
 * \def MBEDTLS_BASE64_C
 *
 * Enable the Base64 module.
 *
 * Module:  library/base64.c
 * Caller:  library/pem.c
 *
 * This module is required for PEM support (required by X.509).
 */
#define MBEDTLS_BASE64_C

/**
 * \def MBEDTLS_OID_C
 *
 * Enable the OID database.
 *
 * Module:  library/oid.c
 * Caller:  library/asn1write.c
 *          library/pkcs5.c
 *          library/pkparse.c
 *          library/pkwrite.c
 *          library/rsa.c
 *          library/x509.c
 *          library/x509_create.c
 *          library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 *
 * This modules translates between OIDs and internal values.
 */
#define MBEDTLS_OID_C

/**
 * \def MBEDTLS_PEM_PARSE_C
 *
 * Enable PEM decoding / parsing.
 *
 * Module:  library/pem.c
 * Caller:  library/dhm.c
 *          library/pkparse.c
 *          library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: MBEDTLS_BASE64_C
 *           optionally MBEDTLS_MD5_C, or PSA Crypto with MD5 (see below)
 *
 * \warning When parsing password-protected files, if MD5 is provided only by
 * a PSA driver, you must call psa_crypto_init() before the first file.
 *
 * This modules adds support for decoding / parsing PEM files.
 */
#define MBEDTLS_PEM_PARSE_C

/**
 * \def MBEDTLS_PEM_WRITE_C
 *
 * Enable PEM encoding / writing.
 *
 * Module:  library/pem.c
 * Caller:  library/pkwrite.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 *
 * Requires: MBEDTLS_BASE64_C
 *
 * This modules adds support for encoding / writing PEM files.
 */
#define MBEDTLS_PEM_WRITE_C

/** \} name SECTION: Data format support */

/**
 * \name SECTION: PSA core
 *
 * This section sets PSA specific settings.
 * \{
 */

/**
 * \def MBEDTLS_ENTROPY_C
 *
 * Enable the platform-specific entropy code.
 *
 * Module:  library/entropy.c
 * Caller:
 *
 * Requires: MBEDTLS_SHA512_C or MBEDTLS_SHA256_C
 *
 * This module provides a generic entropy pool
 */
#define MBEDTLS_ENTROPY_C

/**
 * \def MBEDTLS_ENTROPY_FORCE_SHA256
 *
 * Force the entropy accumulator to use a SHA-256 accumulator instead of the
 * default SHA-512 based one (if both are available).
 *
 * Requires: MBEDTLS_SHA256_C
 *
 * On 32-bit systems SHA-256 can be much faster than SHA-512. Use this option
 * if you have performance concerns.
 *
 * This option is only useful if both MBEDTLS_SHA256_C and
 * MBEDTLS_SHA512_C are defined. Otherwise the available hash module is used.
 */
//#define MBEDTLS_ENTROPY_FORCE_SHA256

/**
 * \def MBEDTLS_ENTROPY_HARDWARE_ALT
 *
 * Uncomment this macro to let Mbed TLS use your own implementation of a
 * hardware entropy collector.
 *
 * Your function must be called \c mbedtls_hardware_poll(), have the same
 * prototype as declared in library/entropy_poll.h, and accept NULL as first
 * argument.
 *
 * Uncomment to use your own hardware entropy collector.
 */
//#define MBEDTLS_ENTROPY_HARDWARE_ALT

/**
 * \def MBEDTLS_ENTROPY_NV_SEED
 *
 * Enable the non-volatile (NV) seed file-based entropy source.
 * (Also enables the NV seed read/write functions in the platform layer)
 *
 * This is crucial (if not required) on systems that do not have a
 * cryptographic entropy source (in hardware or kernel) available.
 *
 * Requires: MBEDTLS_ENTROPY_C, MBEDTLS_PLATFORM_C
 *
 * \note The read/write functions that are used by the entropy source are
 *       determined in the platform layer, and can be modified at runtime and/or
 *       compile-time depending on the flags (MBEDTLS_PLATFORM_NV_SEED_*) used.
 *
 * \note If you use the default implementation functions that read a seedfile
 *       with regular fopen(), please make sure you make a seedfile with the
 *       proper name (defined in MBEDTLS_PLATFORM_STD_NV_SEED_FILE) and at
 *       least MBEDTLS_ENTROPY_BLOCK_SIZE bytes in size that can be read from
 *       and written to or you will get an entropy source error! The default
 *       implementation will only use the first MBEDTLS_ENTROPY_BLOCK_SIZE
 *       bytes from the file.
 *
 * \note The entropy collector will write to the seed file before entropy is
 *       given to an external source, to update it.
 */
//#define MBEDTLS_ENTROPY_NV_SEED

/**
 * \def MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
 *
 * Do not add default entropy sources in mbedtls_entropy_init().
 *
 * This is useful to have more control over the added entropy sources in an
 * application.
 *
 * Uncomment this macro to prevent loading of default entropy functions.
 */
//#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES

/**
 * \def MBEDTLS_NO_PLATFORM_ENTROPY
 *
 * Do not use built-in platform entropy functions.
 * This is useful if your platform does not support
 * standards like the /dev/urandom or Windows CryptoAPI.
 *
 * Uncomment this macro to disable the built-in platform entropy functions.
 */
//#define MBEDTLS_NO_PLATFORM_ENTROPY

/**
 * \def MBEDTLS_PSA_CRYPTO_C
 *
 * Enable the Platform Security Architecture cryptography API.
 *
 * Module:  library/psa_crypto.c
 *
 * Requires: either MBEDTLS_CTR_DRBG_C and MBEDTLS_ENTROPY_C,
 *           or MBEDTLS_HMAC_DRBG_C and MBEDTLS_ENTROPY_C,
 *           or MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG.
 * Auto-enables: MBEDTLS_CIPHER_C if any unauthenticated (ie, non-AEAD) cipher
 *               is enabled in PSA (unless it's fully accelerated, see
 *               docs/driver-only-builds.md about that).
 */
#define MBEDTLS_PSA_CRYPTO_C

/**
 * \def MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS
 *
 * Assume all buffers passed to PSA functions are owned exclusively by the
 * PSA function and are not stored in shared memory.
 *
 * This option may be enabled if all buffers passed to any PSA function reside
 * in memory that is accessible only to the PSA function during its execution.
 *
 * This option MUST be disabled whenever buffer arguments are in memory shared
 * with an untrusted party, for example where arguments to PSA calls are passed
 * across a trust boundary.
 *
 * \note Enabling this option reduces memory usage and code size.
 *
 * \note Enabling this option causes overlap of input and output buffers
 *       not to be supported by PSA functions.
 */
//#define MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS

/** \def MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
 *
 * Enable support for platform built-in keys. If you enable this feature,
 * you must implement the function mbedtls_psa_platform_get_builtin_key().
 * See the documentation of that function for more information.
 *
 * Built-in keys are typically derived from a hardware unique key or
 * stored in a secure element.
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C.
 *
 * \warning This interface is experimental and may change or be removed
 * without notice.
 */
//#define MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS

/** \def MBEDTLS_PSA_CRYPTO_CLIENT
 *
 * Enable support for PSA crypto client.
 *
 * \note This option allows to include the code necessary for a PSA
 *       crypto client when the PSA crypto implementation is not included in
 *       the library (MBEDTLS_PSA_CRYPTO_C disabled). The code included is the
 *       code to set and get PSA key attributes.
 *       The development of PSA drivers partially relying on the library to
 *       fulfill the hardware gaps is another possible usage of this option.
 *
 * \warning This interface is experimental and may change or be removed
 * without notice.
 */
//#define MBEDTLS_PSA_CRYPTO_CLIENT

/** \def MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
 *
 * Make the PSA Crypto module use an external random generator provided
 * by a driver, instead of Mbed TLS's entropy and DRBG modules.
 *
 * \note This random generator must deliver random numbers with cryptographic
 *       quality and high performance. It must supply unpredictable numbers
 *       with a uniform distribution. The implementation of this function
 *       is responsible for ensuring that the random generator is seeded
 *       with sufficient entropy. If you have a hardware TRNG which is slow
 *       or delivers non-uniform output, declare it as an entropy source
 *       with mbedtls_entropy_add_source() instead of enabling this option.
 *
 * If you enable this option, you must configure the type
 * ::mbedtls_psa_external_random_context_t in psa/crypto_platform.h
 * and define a function called mbedtls_psa_external_get_random()
 * with the following prototype:
 * ```
 * psa_status_t mbedtls_psa_external_get_random(
 *     mbedtls_psa_external_random_context_t *context,
 *     uint8_t *output, size_t output_size, size_t *output_length);
 * );
 * ```
 * The \c context value is initialized to 0 before the first call.
 * The function must fill the \c output buffer with \c output_size bytes
 * of random data and set \c *output_length to \c output_size.
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C
 *
 * \warning If you enable this option, code that uses the PSA cryptography
 *          interface will not use any of the entropy sources set up for
 *          the entropy module, nor the NV seed that MBEDTLS_ENTROPY_NV_SEED
 *          enables.
 *
 * \note This option is experimental and may be removed without notice.
 */
//#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG

/* MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
 *
 * Enable key identifiers that encode a key owner identifier.
 *
 * The owner of a key is identified by a value of type ::mbedtls_key_owner_id_t
 * which is currently hard-coded to be int32_t.
 *
 * Note that this option is meant for internal use only and may be removed
 * without notice.
 */
//#define MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER

/**
 * \def MBEDTLS_PSA_CRYPTO_SPM
 *
 * When MBEDTLS_PSA_CRYPTO_SPM is defined, the code is built for SPM (Secure
 * Partition Manager) integration which separates the code into two parts: a
 * NSPE (Non-Secure Process Environment) and an SPE (Secure Process
 * Environment).
 *
 * If you enable this option, your build environment must include a header
 * file `"crypto_spe.h"` (either in the `psa` subdirectory of the Mbed TLS
 * header files, or in another directory on the compiler's include search
 * path). Alternatively, your platform may customize the header
 * `psa/crypto_platform.h`, in which case it can skip or replace the
 * inclusion of `"crypto_spe.h"`.
 *
 * Module:  library/psa_crypto.c
 * Requires: MBEDTLS_PSA_CRYPTO_C
 *
 */
//#define MBEDTLS_PSA_CRYPTO_SPM

/**
 * \def MBEDTLS_PSA_CRYPTO_STORAGE_C
 *
 * Enable the Platform Security Architecture persistent key storage.
 *
 * Module:  library/psa_crypto_storage.c
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C,
 *           either MBEDTLS_PSA_ITS_FILE_C or a native implementation of
 *           the PSA ITS interface
 */
#define MBEDTLS_PSA_CRYPTO_STORAGE_C

/**
 * \def MBEDTLS_PSA_INJECT_ENTROPY
 *
 * Enable support for entropy injection at first boot. This feature is
 * required on systems that do not have a built-in entropy source (TRNG).
 * This feature is currently not supported on systems that have a built-in
 * entropy source.
 *
 * Requires: MBEDTLS_PSA_CRYPTO_STORAGE_C, MBEDTLS_ENTROPY_NV_SEED
 *
 */
//#define MBEDTLS_PSA_INJECT_ENTROPY

/**
 * \def MBEDTLS_PSA_ITS_FILE_C
 *
 * Enable the emulation of the Platform Security Architecture
 * Internal Trusted Storage (PSA ITS) over files.
 *
 * Module:  library/psa_its_file.c
 *
 * Requires: MBEDTLS_FS_IO
 */
#define MBEDTLS_PSA_ITS_FILE_C

/**
 * \def MBEDTLS_PSA_KEY_STORE_DYNAMIC
 *
 * Dynamically resize the PSA key store to accommodate any number of
 * volatile keys (until the heap memory is exhausted).
 *
 * If this option is disabled, the key store has a fixed size
 * #MBEDTLS_PSA_KEY_SLOT_COUNT for volatile keys and loaded persistent keys
 * together.
 *
 * This option has no effect when #MBEDTLS_PSA_CRYPTO_C is disabled.
 *
 * Module:  library/psa_crypto.c
 * Requires: MBEDTLS_PSA_CRYPTO_C
 */
#define MBEDTLS_PSA_KEY_STORE_DYNAMIC

/**
 * \def MBEDTLS_PSA_STATIC_KEY_SLOTS
 *
 * Statically preallocate memory to store keys' material in PSA instead
 * of allocating it dynamically when required. This allows builds without a
 * heap, if none of the enabled cryptographic implementations or other features
 * require it.
 * This feature affects both volatile and persistent keys which means that
 * it's not possible to persistently store a key which is larger than
 * #MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE.
 *
 * \note This feature comes with a (potentially) higher RAM usage since:
 *       - All the key slots are allocated no matter if they are used or not.
 *       - Each key buffer's length is #MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE bytes.
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C
 *
 */
//#define MBEDTLS_PSA_STATIC_KEY_SLOTS

/* Entropy options */
//#define MBEDTLS_ENTROPY_MAX_GATHER                128 /**< Maximum amount requested from entropy sources */
//#define MBEDTLS_ENTROPY_MAX_SOURCES                20 /**< Maximum number of sources supported */
//#define MBEDTLS_ENTROPY_MIN_HARDWARE               32 /**< Default minimum number of bytes required for the hardware entropy source mbedtls_hardware_poll() before entropy is released */

/**
 * \def MBEDTLS_PSA_CRYPTO_PLATFORM_FILE
 *
 * If defined, this is a header which will be included instead of
 * `"psa/crypto_platform.h"`. This file should declare the same identifiers
 * as the one in Mbed TLS, but with definitions adapted to the platform on
 * which the library code will run.
 *
 * \note The required content of this header can vary from one version of
 *       Mbed TLS to the next. Integrators who provide an alternative file
 *       should review the changes in the original file whenever they
 *       upgrade Mbed TLS.
 *
 * This macro is expanded after an <tt>\#include</tt> directive. This is a popular but
 * non-standard feature of the C language, so this feature is only available
 * with compilers that perform macro expansion on an <tt>\#include</tt> line.
 *
 * The value of this symbol is typically a path in double quotes, either
 * absolute or relative to a directory on the include search path.
 */
//#define MBEDTLS_PSA_CRYPTO_PLATFORM_FILE "psa/crypto_platform_alt.h"

/**
 * \def MBEDTLS_PSA_CRYPTO_STRUCT_FILE
 *
 * If defined, this is a header which will be included instead of
 * `"psa/crypto_struct.h"`. This file should declare the same identifiers
 * as the one in Mbed TLS, but with definitions adapted to the environment
 * in which the library code will run. The typical use for this feature
 * is to provide alternative type definitions on the client side in
 * client-server integrations of PSA crypto, where operation structures
 * contain handles instead of cryptographic data.
 *
 * \note The required content of this header can vary from one version of
 *       Mbed TLS to the next. Integrators who provide an alternative file
 *       should review the changes in the original file whenever they
 *       upgrade Mbed TLS.
 *
 * This macro is expanded after an <tt>\#include</tt> directive. This is a popular but
 * non-standard feature of the C language, so this feature is only available
 * with compilers that perform macro expansion on an <tt>\#include</tt> line.
 *
 * The value of this symbol is typically a path in double quotes, either
 * absolute or relative to a directory on the include search path.
 */
//#define MBEDTLS_PSA_CRYPTO_STRUCT_FILE "psa/crypto_struct_alt.h"

/** \def MBEDTLS_PSA_KEY_SLOT_COUNT
 *
 * When #MBEDTLS_PSA_KEY_STORE_DYNAMIC is disabled,
 * the maximum amount of PSA keys simultaneously in memory. This counts all
 * volatile keys, plus loaded persistent keys.
 *
 * When #MBEDTLS_PSA_KEY_STORE_DYNAMIC is enabled,
 * the maximum number of loaded persistent keys.
 *
 * Currently, persistent keys do not need to be loaded all the time while
 * a multipart operation is in progress, only while the operation is being
 * set up. This may change in future versions of the library.
 *
 * Currently, the library traverses of the whole table on each access to a
 * persistent key. Therefore large values may cause poor performance.
 *
 * This option has no effect when #MBEDTLS_PSA_CRYPTO_C is disabled.
 */
//#define MBEDTLS_PSA_KEY_SLOT_COUNT 32

/**
 * \def MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE
 *
 * Define the size (in bytes) of each static key buffer when
 * #MBEDTLS_PSA_STATIC_KEY_SLOTS is set. If not
 * explicitly defined then it's automatically guessed from available PSA keys
 * enabled in the build through PSA_WANT_xxx symbols.
 * If required by the application this parameter can be set to higher values
 * in order to store larger objects (ex: raw keys), but please note that this
 * will increase RAM usage.
 */
//#define MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE       256

/** \} name SECTION: PSA core */

/**
 * \name SECTION: Builtin drivers
 *
 * This section sets driver specific settings.
 * \{
 */

/**
 * \def MBEDTLS_AESNI_C
 *
 * Enable AES-NI support on x86-64 or x86-32.
 *
 * \note AESNI is only supported with certain compilers and target options:
 * - Visual Studio: supported
 * - GCC, x86-64, target not explicitly supporting AESNI:
 *   requires MBEDTLS_HAVE_ASM.
 * - GCC, x86-32, target not explicitly supporting AESNI:
 *   not supported.
 * - GCC, x86-64 or x86-32, target supporting AESNI: supported.
 *   For this assembly-less implementation, you must currently compile
 *   `library/aesni.c` and `library/aes.c` with machine options to enable
 *   SSE2 and AESNI instructions: `gcc -msse2 -maes -mpclmul` or
 *   `clang -maes -mpclmul`.
 * - Non-x86 targets: this option is silently ignored.
 * - Other compilers: this option is silently ignored.
 *
 * \note
 * Above, "GCC" includes compatible compilers such as Clang.
 * The limitations on target support are likely to be relaxed in the future.
 *
 * Module:  library/aesni.c
 * Caller:  library/aes.c
 *
 * Requires: MBEDTLS_HAVE_ASM (on some platforms, see note)
 *
 * This modules adds support for the AES-NI instructions on x86.
 */
#define MBEDTLS_AESNI_C

/**
 * \def MBEDTLS_AESCE_C
 *
 * Enable AES cryptographic extension support on Armv8.
 *
 * Module:  library/aesce.c
 * Caller:  library/aes.c
 *
 * Requires: MBEDTLS_AES_C
 *
 * \warning Runtime detection only works on Linux. For non-Linux operating
 *          system, Armv8-A Cryptographic Extensions must be supported by
 *          the CPU when this option is enabled.
 *
 * \note    Minimum compiler versions for this feature when targeting aarch64
 *          are Clang 4.0; armclang 6.6; GCC 6.0; or MSVC 2019 version 16.11.2.
 *          Minimum compiler versions for this feature when targeting 32-bit
 *          Arm or Thumb are Clang 11.0; armclang 6.20; or GCC 6.0.
 *
 * \note \c CFLAGS must be set to a minimum of \c -march=armv8-a+crypto for
 * armclang <= 6.9
 *
 * This module adds support for the AES Armv8-A Cryptographic Extensions on Armv8 systems.
 */
#define MBEDTLS_AESCE_C

/**
 * \def MBEDTLS_AES_ROM_TABLES
 *
 * Use precomputed AES tables stored in ROM.
 *
 * Uncomment this macro to use precomputed AES tables stored in ROM.
 * Comment this macro to generate AES tables in RAM at runtime.
 *
 * Tradeoff: Using precomputed ROM tables reduces RAM usage by ~8kb
 * (or ~2kb if \c MBEDTLS_AES_FEWER_TABLES is used) and reduces the
 * initialization time before the first AES operation can be performed.
 * It comes at the cost of additional ~8kb ROM use (resp. ~2kb if \c
 * MBEDTLS_AES_FEWER_TABLES below is used), and potentially degraded
 * performance if ROM access is slower than RAM access.
 *
 * This option is independent of \c MBEDTLS_AES_FEWER_TABLES.
 */
//#define MBEDTLS_AES_ROM_TABLES

/**
 * \def MBEDTLS_AES_FEWER_TABLES
 *
 * Use less ROM/RAM for AES tables.
 *
 * Uncommenting this macro omits 75% of the AES tables from
 * ROM / RAM (depending on the value of \c MBEDTLS_AES_ROM_TABLES)
 * by computing their values on the fly during operations
 * (the tables are entry-wise rotations of one another).
 *
 * Tradeoff: Uncommenting this reduces the RAM / ROM footprint
 * by ~6kb but at the cost of more arithmetic operations during
 * runtime. Specifically, one has to compare 4 accesses within
 * different tables to 4 accesses with additional arithmetic
 * operations within the same table. The performance gain/loss
 * depends on the system and memory details.
 *
 * This option is independent of \c MBEDTLS_AES_ROM_TABLES.
 */
//#define MBEDTLS_AES_FEWER_TABLES

/**
 * \def MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH
 *
 * Use only 128-bit keys in AES operations to save ROM.
 *
 * Uncomment this macro to remove support for AES operations that use 192-
 * or 256-bit keys.
 *
 * Uncommenting this macro reduces the size of AES code by ~300 bytes
 * on v8-M/Thumb2.
 *
 * Module:  library/aes.c
 *
 * Requires: MBEDTLS_AES_C
 */
//#define MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH

/*
 * Disable plain C implementation for AES.
 *
 * When the plain C implementation is enabled, and an implementation using a
 * special CPU feature (such as MBEDTLS_AESCE_C) is also enabled, runtime
 * detection will be used to select between them.
 *
 * If only one implementation is present, runtime detection will not be used.
 * This configuration will crash at runtime if running on a CPU without the
 * necessary features. It will not build unless at least one of MBEDTLS_AESCE_C
 * and/or MBEDTLS_AESNI_C is enabled & present in the build.
 */
//#define MBEDTLS_AES_USE_HARDWARE_ONLY

/**
 * \def MBEDTLS_BLOCK_CIPHER_NO_DECRYPT
 *
 * Remove decryption operation for AES, ARIA and Camellia block cipher.
 *
 * \note  This feature is incompatible with insecure block cipher,
 *        MBEDTLS_DES_C, and cipher modes which always require decryption
 *        operation, MBEDTLS_CIPHER_MODE_CBC, MBEDTLS_CIPHER_MODE_XTS and
 *        MBEDTLS_NIST_KW_C. This feature is incompatible with following
 *        supported PSA equivalence PSA_WANT_ALG_ECB_NO_PADDING,
 *        PSA_WANT_ALG_CBC_NO_PADDING, PSA_WANT_ALG_CBC_PKCS7 and
 *        PSA_WANT_KEY_TYPE_DES.
 *
 * Module:  library/aes.c
 *          library/aesce.c
 *          library/aesni.c
 *          library/aria.c
 *          library/camellia.c
 *          library/cipher.c
 */
//#define MBEDTLS_BLOCK_CIPHER_NO_DECRYPT

/**
 * \def MBEDTLS_CAMELLIA_SMALL_MEMORY
 *
 * Use less ROM for the Camellia implementation (saves about 768 bytes).
 *
 * Uncomment this macro to use less memory for Camellia.
 */
//#define MBEDTLS_CAMELLIA_SMALL_MEMORY

/**
 * Enable the verified implementations of ECDH primitives from Project Everest
 * (currently only Curve25519). This feature changes the layout of ECDH
 * contexts and therefore is a compatibility break for applications that access
 * fields of a mbedtls_ecdh_context structure directly. See also
 * MBEDTLS_ECDH_LEGACY_CONTEXT in include/mbedtls/ecdh.h.
 *
 * The Everest code is provided under the Apache 2.0 license only; therefore enabling this
 * option is not compatible with taking the library under the GPL v2.0-or-later license.
 */
//#define MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED

/**
 * \def MBEDTLS_ECP_NIST_OPTIM
 *
 * Enable specific 'modulo p' routines for each NIST prime.
 * Depending on the prime and architecture, makes operations 4 to 8 times
 * faster on the corresponding curve.
 *
 * Comment this macro to disable NIST curves optimisation.
 */
#define MBEDTLS_ECP_NIST_OPTIM

/**
 * \def MBEDTLS_ECP_RESTARTABLE
 *
 * Enable "non-blocking" ECC operations that can return early and be resumed.
 *
 * This allows various functions to pause by returning
 * #MBEDTLS_ERR_ECP_IN_PROGRESS (or, for functions in the SSL module,
 * #MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) and then be called later again in
 * order to further progress and eventually complete their operation. This is
 * controlled through mbedtls_ecp_set_max_ops() which limits the maximum
 * number of ECC operations a function may perform before pausing; see
 * mbedtls_ecp_set_max_ops() for more information.
 *
 * This is useful in non-threaded environments if you want to avoid blocking
 * for too long on ECC (and, hence, X.509 or SSL/TLS) operations.
 *
 * This option:
 * - Adds xxx_restartable() variants of existing operations in the
 *   following modules, with corresponding restart context types:
 *   - ECP (for Short Weierstrass curves only): scalar multiplication (mul),
 *     linear combination (muladd);
 *   - ECDSA: signature generation & verification;
 *   - PK: signature generation & verification;
 *   - X509: certificate chain verification.
 * - Adds mbedtls_ecdh_enable_restart() in the ECDH module.
 * - Changes the behaviour of TLS 1.2 clients (not servers) when using the
 *   ECDHE-ECDSA key exchange (not other key exchanges) to make all ECC
 *   computations restartable:
 *   - verification of the server's key exchange signature;
 *   - verification of the server's certificate chain;
 *   - generation of the client's signature if client authentication is used,
 *     with an ECC key/certificate.
 *
 * \note  In the cases above, the usual SSL/TLS functions, such as
 *        mbedtls_ssl_handshake(), can now return
 *        MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS.
 *
 * \note  When this option is enabled, restartable operations in PK, X.509
 *        and TLS (see above) are not using PSA. On the other hand, ECDH
 *        computations in TLS are using PSA, and are not restartable. These
 *        are temporary limitations that should be lifted in the future. (See
 *        https://github.com/Mbed-TLS/mbedtls/issues/9784 and
 *        https://github.com/Mbed-TLS/mbedtls/issues/9817)
 *
 * Requires: MBEDTLS_ECP_C
 *
 * Uncomment this macro to enable restartable ECC computations.
 */
//#define MBEDTLS_ECP_RESTARTABLE

/**
 * Uncomment to enable using new bignum code in the ECC modules.
 *
 * \warning This is currently experimental, incomplete and therefore should not
 * be used in production.
 */
//#define MBEDTLS_ECP_WITH_MPI_UINT

/**
 * \def MBEDTLS_GCM_LARGE_TABLE
 *
 * Enable large pre-computed tables for  Galois/Counter Mode (GCM).
 * Can significantly increase throughput on systems without GCM hardware
 * acceleration (e.g., AESNI, AESCE).
 *
 * The mbedtls_gcm_context size will increase by 3840 bytes.
 * The code size will increase by roughly 344 bytes.
 *
 * Module:  library/gcm.c
 *
 * Requires: MBEDTLS_GCM_C
 */
//#define MBEDTLS_GCM_LARGE_TABLE

/**
 * \def MBEDTLS_HAVE_ASM
 *
 * The compiler has support for asm().
 *
 * Requires support for asm() in compiler.
 *
 * Used in:
 *      library/aesni.h
 *      library/aria.c
 *      library/bn_mul.h
 *      library/constant_time.c
 *
 * Required by:
 *      MBEDTLS_AESCE_C
 *      MBEDTLS_AESNI_C (on some platforms)
 *
 * Comment to disable the use of assembly code.
 */
#define MBEDTLS_HAVE_ASM

/**
 * \def MBEDTLS_HAVE_SSE2
 *
 * CPU supports SSE2 instruction set.
 *
 * Uncomment if the CPU supports SSE2 (IA-32 specific).
 */
//#define MBEDTLS_HAVE_SSE2

/**
 * \def MBEDTLS_NO_UDBL_DIVISION
 *
 * The platform lacks support for double-width integer division (64-bit
 * division on a 32-bit platform, 128-bit division on a 64-bit platform).
 *
 * Used in:
 *      include/mbedtls/bignum.h
 *      library/bignum.c
 *
 * The bignum code uses double-width division to speed up some operations.
 * Double-width division is often implemented in software that needs to
 * be linked with the program. The presence of a double-width integer
 * type is usually detected automatically through preprocessor macros,
 * but the automatic detection cannot know whether the code needs to
 * and can be linked with an implementation of division for that type.
 * By default division is assumed to be usable if the type is present.
 * Uncomment this option to prevent the use of double-width division.
 *
 * Note that division for the native integer type is always required.
 * Furthermore, a 64-bit type is always required even on a 32-bit
 * platform, but it need not support multiplication or division. In some
 * cases it is also desirable to disable some double-width operations. For
 * example, if double-width division is implemented in software, disabling
 * it can reduce code size in some embedded targets.
 */
//#define MBEDTLS_NO_UDBL_DIVISION

/**
 * \def MBEDTLS_NO_64BIT_MULTIPLICATION
 *
 * The platform lacks support for 32x32 -> 64-bit multiplication.
 *
 * Used in:
 *      library/poly1305.c
 *
 * Some parts of the library may use multiplication of two unsigned 32-bit
 * operands with a 64-bit result in order to speed up computations. On some
 * platforms, this is not available in hardware and has to be implemented in
 * software, usually in a library provided by the toolchain.
 *
 * Sometimes it is not desirable to have to link to that library. This option
 * removes the dependency of that library on platforms that lack a hardware
 * 64-bit multiplier by embedding a software implementation in Mbed TLS.
 *
 * Note that depending on the compiler, this may decrease performance compared
 * to using the library function provided by the toolchain.
 */
//#define MBEDTLS_NO_64BIT_MULTIPLICATION

/**
 * Uncomment to enable p256-m. This is an alternative implementation of
 * key generation, ECDH and (randomized) ECDSA on the curve SECP256R1.
 * Compared to the default implementation:
 *
 * - p256-m has a much smaller code size and RAM footprint.
 * - p256-m is only available via the PSA API. This includes the pk module.
 * - p256-m does not support deterministic ECDSA, EC-JPAKE, custom protocols
 *   over the core arithmetic, or deterministic derivation of keys.
 *
 * We recommend enabling this option if your application uses the PSA API
 * and the only elliptic curve support it needs is ECDH and ECDSA over
 * SECP256R1.
 *
 * If you enable this option, you do not need to enable any ECC-related
 * MBEDTLS_xxx option. You do need to separately request support for the
 * cryptographic mechanisms through the PSA API:
 * - #MBEDTLS_PSA_CRYPTO_C for PSA-based configuration;
 * - #PSA_WANT_ECC_SECP_R1_256;
 * - #PSA_WANT_ALG_ECDH and/or #PSA_WANT_ALG_ECDSA as needed;
 * - #PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY, #PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC,
 *   #PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT,
 *   #PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT and/or
 *   #PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE as needed.
 *
 * \note To benefit from the smaller code size of p256-m, make sure that you
 *       do not enable any ECC-related option not supported by p256-m: this
 *       would cause the built-in ECC implementation to be built as well, in
 *       order to provide the required option.
 *       Make sure #PSA_WANT_ALG_DETERMINISTIC_ECDSA, #PSA_WANT_ALG_JPAKE and
 *       #PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE, and curves other than
 *       SECP256R1 are disabled as they are not supported by this driver.
 *       Also, avoid defining #MBEDTLS_PK_PARSE_EC_COMPRESSED or
 *       #MBEDTLS_PK_PARSE_EC_EXTENDED as those currently require a subset of
 *       the built-in ECC implementation, see docs/driver-only-builds.md.
 */
//#define MBEDTLS_PSA_P256M_DRIVER_ENABLED

/**
 * \def MBEDTLS_RSA_NO_CRT
 *
 * Do not use the Chinese Remainder Theorem
 * for the RSA private operation.
 *
 * Uncomment this macro to disable the use of CRT in RSA.
 *
 */
//#define MBEDTLS_RSA_NO_CRT

/**
 * \def MBEDTLS_SHA256_SMALLER
 *
 * Enable an implementation of SHA-256 that has lower ROM footprint but also
 * lower performance.
 *
 * The default implementation is meant to be a reasonable compromise between
 * performance and size. This version optimizes more aggressively for size at
 * the expense of performance. Eg on Cortex-M4 it reduces the size of
 * mbedtls_sha256_process() from ~2KB to ~0.5KB for a performance hit of about
 * 30%.
 *
 * Uncomment to enable the smaller implementation of SHA256.
 */
//#define MBEDTLS_SHA256_SMALLER

/**
 * \def MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
 *
 * Enable acceleration of the SHA-256 and SHA-224 cryptographic hash algorithms
 * with the ARMv8 cryptographic extensions if they are available at runtime.
 * If not, the library will fall back to the C implementation.
 *
 * \note If MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT is defined when building
 * for a non-Armv8-A build it will be silently ignored.
 *
 * \note    Minimum compiler versions for this feature are Clang 4.0,
 * armclang 6.6 or GCC 6.0.
 *
 * \note \c CFLAGS must be set to a minimum of \c -march=armv8-a+crypto for
 * armclang <= 6.9
 *
 * \note This was previously known as MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT.
 * That name is deprecated, but may still be used as an alternative form for this
 * option.
 *
 * \warning MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT cannot be defined at the
 * same time as MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY.
 *
 * Requires: MBEDTLS_SHA256_C.
 *
 * Module:  library/sha256.c
 *
 * Uncomment to have the library check for the Armv8-A SHA-256 crypto extensions
 * and use them if available.
 */
//#define MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT

/**
 * \def MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT
 *
 * \deprecated This is now known as MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT.
 * This name is now deprecated, but may still be used as an alternative form for
 * this option.
 */
//#define MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT

/**
 * \def MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY
 *
 * Enable acceleration of the SHA-256 and SHA-224 cryptographic hash algorithms
 * with the ARMv8 cryptographic extensions, which must be available at runtime
 * or else an illegal instruction fault will occur.
 *
 * \note This allows builds with a smaller code size than with
 * MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
 *
 * \note    Minimum compiler versions for this feature are Clang 4.0,
 * armclang 6.6 or GCC 6.0.
 *
 * \note \c CFLAGS must be set to a minimum of \c -march=armv8-a+crypto for
 * armclang <= 6.9
 *
 * \note This was previously known as MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY.
 * That name is deprecated, but may still be used as an alternative form for this
 * option.
 *
 * \warning MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY cannot be defined at the same
 * time as MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT.
 *
 * Requires: MBEDTLS_SHA256_C.
 *
 * Module:  library/sha256.c
 *
 * Uncomment to have the library use the Armv8-A SHA-256 crypto extensions
 * unconditionally.
 */
//#define MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY

/**
 * \def MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY
 *
 * \deprecated This is now known as MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY.
 * This name is now deprecated, but may still be used as an alternative form for
 * this option.
 */
//#define MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY

/**
 * \def MBEDTLS_SHA512_SMALLER
 *
 * Enable an implementation of SHA-512 that has lower ROM footprint but also
 * lower performance.
 *
 * Uncomment to enable the smaller implementation of SHA512.
 */
//#define MBEDTLS_SHA512_SMALLER

/**
 * \def MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT
 *
 * Enable acceleration of the SHA-512 and SHA-384 cryptographic hash algorithms
 * with the ARMv8 cryptographic extensions if they are available at runtime.
 * If not, the library will fall back to the C implementation.
 *
 * \note If MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT is defined when building
 * for a non-Aarch64 build it will be silently ignored.
 *
 * \note    Minimum compiler versions for this feature are Clang 7.0,
 * armclang 6.9 or GCC 8.0.
 *
 * \note \c CFLAGS must be set to a minimum of \c -march=armv8.2-a+sha3 for
 * armclang 6.9
 *
 * \warning MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT cannot be defined at the
 * same time as MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY.
 *
 * Requires: MBEDTLS_SHA512_C.
 *
 * Module:  library/sha512.c
 *
 * Uncomment to have the library check for the A64 SHA-512 crypto extensions
 * and use them if available.
 */
//#define MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT

/**
 * \def MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY
 *
 * Enable acceleration of the SHA-512 and SHA-384 cryptographic hash algorithms
 * with the ARMv8 cryptographic extensions, which must be available at runtime
 * or else an illegal instruction fault will occur.
 *
 * \note This allows builds with a smaller code size than with
 * MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT
 *
 * \note    Minimum compiler versions for this feature are Clang 7.0,
 * armclang 6.9 or GCC 8.0.
 *
 * \note \c CFLAGS must be set to a minimum of \c -march=armv8.2-a+sha3 for
 * armclang 6.9
 *
 * \warning MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY cannot be defined at the same
 * time as MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT.
 *
 * Requires: MBEDTLS_SHA512_C.
 *
 * Module:  library/sha512.c
 *
 * Uncomment to have the library use the A64 SHA-512 crypto extensions
 * unconditionally.
 */
//#define MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY

/* ECP options */
//#define MBEDTLS_ECP_FIXED_POINT_OPTIM      1 /**< Enable fixed-point speed-up */
//#define MBEDTLS_ECP_WINDOW_SIZE            4 /**< Maximum window size used */

/* MPI / BIGNUM options */
//#define MBEDTLS_MPI_MAX_SIZE            1024 /**< Maximum number of bytes for usable MPIs. */
//#define MBEDTLS_MPI_WINDOW_SIZE            2 /**< Maximum window size used. */

/* RSA OPTIONS */
//#define MBEDTLS_RSA_GEN_KEY_MIN_BITS            1024 /**<  Minimum RSA key size that can be generated in bits (Minimum possible value is 128 bits) */

/** \} name SECTION: Builtin drivers */

/**
 * \name SECTION: Legacy cryptography
 *
 * This section sets legacy settings.
 * \{
 */

/**
 * \def MBEDTLS_AES_C
 *
 * Enable the AES block cipher.
 *
 * Module:  library/aes.c
 * Caller:  library/cipher.c
 *          library/pem.c
 *          library/ctr_drbg.c
 *
 * This module enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256
 *      MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA
 *
 * PEM_PARSE uses AES for decrypting encrypted keys.
 */
#define MBEDTLS_AES_C

/**
 * \def MBEDTLS_ARIA_C
 *
 * Enable the ARIA block cipher.
 *
 * Module:  library/aria.c
 * Caller:  library/cipher.c
 *
 * This module enables the following ciphersuites (if other requisites are
 * enabled as well):
 *
 *      MBEDTLS_TLS_RSA_WITH_ARIA_128_CBC_SHA256
 *      MBEDTLS_TLS_RSA_WITH_ARIA_256_CBC_SHA384
 *      MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256
 *      MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384
 *      MBEDTLS_TLS_RSA_WITH_ARIA_128_GCM_SHA256
 *      MBEDTLS_TLS_RSA_WITH_ARIA_256_GCM_SHA384
 *      MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256
 *      MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384
 *      MBEDTLS_TLS_PSK_WITH_ARIA_128_CBC_SHA256
 *      MBEDTLS_TLS_PSK_WITH_ARIA_256_CBC_SHA384
 *      MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256
 *      MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384
 *      MBEDTLS_TLS_PSK_WITH_ARIA_128_GCM_SHA256
 *      MBEDTLS_TLS_PSK_WITH_ARIA_256_GCM_SHA384
 *      MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256
 *      MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384
 */
#define MBEDTLS_ARIA_C

/**
 * \def MBEDTLS_BIGNUM_C
 *
 * Enable the multi-precision integer library.
 *
 * Module:  library/bignum.c
 *          library/bignum_core.c
 *          library/bignum_mod.c
 *          library/bignum_mod_raw.c
 * Caller:  library/dhm.c
 *          library/ecp.c
 *          library/ecdsa.c
 *          library/rsa.c
 *          library/rsa_alt_helpers.c
 *          library/ssl_tls.c
 *
 * This module is required for RSA, DHM and ECC (ECDH, ECDSA) support.
 */
#define MBEDTLS_BIGNUM_C

/**
 * \def MBEDTLS_CAMELLIA_C
 *
 * Enable the Camellia block cipher.
 *
 * Module:  library/camellia.c
 * Caller:  library/cipher.c
 *
 * This module enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
 *      MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
 *      MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
 *      MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *      MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
 *      MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
 *      MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
 *      MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
 */
#define MBEDTLS_CAMELLIA_C

/**
 * \def MBEDTLS_CCM_C
 *
 * Enable the Counter with CBC-MAC (CCM) mode for 128-bit block cipher.
 *
 * Module:  library/ccm.c
 *
 * Requires: MBEDTLS_CIPHER_C, MBEDTLS_AES_C or MBEDTLS_CAMELLIA_C or
 *                             MBEDTLS_ARIA_C
 *
 * This module enables the AES-CCM ciphersuites, if other requisites are
 * enabled as well.
 */
#define MBEDTLS_CCM_C

/**
 * \def MBEDTLS_CHACHA20_C
 *
 * Enable the ChaCha20 stream cipher.
 *
 * Module:  library/chacha20.c
 */
#define MBEDTLS_CHACHA20_C

/**
 * \def MBEDTLS_CHACHAPOLY_C
 *
 * Enable the ChaCha20-Poly1305 AEAD algorithm.
 *
 * Module:  library/chachapoly.c
 *
 * This module requires: MBEDTLS_CHACHA20_C, MBEDTLS_POLY1305_C
 */
#define MBEDTLS_CHACHAPOLY_C

/**
 * \def MBEDTLS_CIPHER_C
 *
 * Enable the generic cipher layer.
 *
 * Module:  library/cipher.c
 * Caller:  library/ccm.c
 *          library/cmac.c
 *          library/gcm.c
 *          library/nist_kw.c
 *          library/pkcs12.c
 *          library/pkcs5.c
 *          library/psa_crypto_aead.c
 *          library/psa_crypto_mac.c
 *          library/ssl_ciphersuites.c
 *          library/ssl_msg.c
 * Auto-enabled by: MBEDTLS_PSA_CRYPTO_C depending on which ciphers are enabled
 *                  (see the documentation of that option for details).
 *
 * Uncomment to enable generic cipher wrappers.
 */
#define MBEDTLS_CIPHER_C

/**
 * \def MBEDTLS_CIPHER_MODE_CBC
 *
 * Enable Cipher Block Chaining mode (CBC) for symmetric ciphers.
 */
#define MBEDTLS_CIPHER_MODE_CBC

/**
 * \def MBEDTLS_CIPHER_MODE_CFB
 *
 * Enable Cipher Feedback mode (CFB) for symmetric ciphers.
 */
#define MBEDTLS_CIPHER_MODE_CFB

/**
 * \def MBEDTLS_CIPHER_MODE_CTR
 *
 * Enable Counter Block Cipher mode (CTR) for symmetric ciphers.
 */
#define MBEDTLS_CIPHER_MODE_CTR

/**
 * \def MBEDTLS_CIPHER_MODE_OFB
 *
 * Enable Output Feedback mode (OFB) for symmetric ciphers.
 */
#define MBEDTLS_CIPHER_MODE_OFB

/**
 * \def MBEDTLS_CIPHER_MODE_XTS
 *
 * Enable Xor-encrypt-xor with ciphertext stealing mode (XTS) for AES.
 */
#define MBEDTLS_CIPHER_MODE_XTS

/**
 * \def MBEDTLS_CIPHER_NULL_CIPHER
 *
 * Enable NULL cipher.
 * Warning: Only do so when you know what you are doing. This allows for
 * encryption or channels without any security!
 *
 * To enable the following ciphersuites:
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_NULL_SHA
 *      MBEDTLS_TLS_ECDH_RSA_WITH_NULL_SHA
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_NULL_SHA
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_NULL_SHA
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA384
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA256
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA
 *      MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA384
 *      MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA256
 *      MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA
 *      MBEDTLS_TLS_RSA_WITH_NULL_SHA256
 *      MBEDTLS_TLS_RSA_WITH_NULL_SHA
 *      MBEDTLS_TLS_RSA_WITH_NULL_MD5
 *      MBEDTLS_TLS_PSK_WITH_NULL_SHA384
 *      MBEDTLS_TLS_PSK_WITH_NULL_SHA256
 *      MBEDTLS_TLS_PSK_WITH_NULL_SHA
 *
 * Uncomment this macro to enable the NULL cipher and ciphersuites
 */
//#define MBEDTLS_CIPHER_NULL_CIPHER

/**
 * \def MBEDTLS_CIPHER_PADDING_PKCS7
 *
 * MBEDTLS_CIPHER_PADDING_XXX: Uncomment or comment macros to add support for
 * specific padding modes in the cipher layer with cipher modes that support
 * padding (e.g. CBC)
 *
 * If you disable all padding modes, only full blocks can be used with CBC.
 *
 * Enable padding modes in the cipher layer.
 */
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS
#define MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN
#define MBEDTLS_CIPHER_PADDING_ZEROS

/**
 * \def MBEDTLS_CMAC_C
 *
 * Enable the CMAC (Cipher-based Message Authentication Code) mode for block
 * ciphers.
 *
 * Module:  library/cmac.c
 *
 * Requires: MBEDTLS_CIPHER_C, MBEDTLS_AES_C or MBEDTLS_DES_C
 *
 */
#define MBEDTLS_CMAC_C

/**
 * \def MBEDTLS_CTR_DRBG_C
 *
 * Enable the CTR_DRBG AES-based random generator.
 * The CTR_DRBG generator uses AES-256 by default.
 * To use AES-128 instead, enable \c MBEDTLS_CTR_DRBG_USE_128_BIT_KEY above.
 *
 * AES support can either be achieved through builtin (MBEDTLS_AES_C) or PSA.
 * Builtin is the default option when MBEDTLS_AES_C is defined otherwise PSA
 * is used.
 *
 * \warning When using PSA, the user should call `psa_crypto_init()` before
 *          using any CTR_DRBG operation (except `mbedtls_ctr_drbg_init()`).
 *
 * \note AES-128 will be used if \c MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH is set.
 *
 * \note To achieve a 256-bit security strength with CTR_DRBG,
 *       you must use AES-256 *and* use sufficient entropy.
 *       See ctr_drbg.h for more details.
 *
 * Module:  library/ctr_drbg.c
 * Caller:
 *
 * Requires: MBEDTLS_AES_C or
 *           (PSA_WANT_KEY_TYPE_AES and PSA_WANT_ALG_ECB_NO_PADDING and
 *            MBEDTLS_PSA_CRYPTO_C)
 *
 * This module provides the CTR_DRBG AES random number generator.
 */
#define MBEDTLS_CTR_DRBG_C

/** \def MBEDTLS_CTR_DRBG_USE_128_BIT_KEY
 *
 * Uncomment this macro to use a 128-bit key in the CTR_DRBG module.
 * Without this, CTR_DRBG uses a 256-bit key
 * unless \c MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH is set.
 */
//#define MBEDTLS_CTR_DRBG_USE_128_BIT_KEY

/**
 * \def MBEDTLS_DES_C
 *
 * Enable the DES block cipher.
 *
 * Module:  library/des.c
 * Caller:  library/pem.c
 *          library/cipher.c
 *
 * PEM_PARSE uses DES/3DES for decrypting encrypted keys.
 *
 * \warning   DES/3DES are considered weak ciphers and their use constitutes a
 *            security risk. We recommend considering stronger ciphers instead.
 */
#define MBEDTLS_DES_C

/**
 * \def MBEDTLS_DHM_C
 *
 * Enable the Diffie-Hellman-Merkle module.
 *
 * Module:  library/dhm.c
 * Caller:  library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * This module is used by the following key exchanges:
 *      DHE-RSA, DHE-PSK
 *
 * \warning    Using DHE constitutes a security risk as it
 *             is not possible to validate custom DH parameters.
 *             If possible, it is recommended users should consider
 *             preferring other methods of key exchange.
 *             See dhm.h for more details.
 *
 */
#define MBEDTLS_DHM_C

/**
 * \def MBEDTLS_ECDH_C
 *
 * Enable the elliptic curve Diffie-Hellman library.
 *
 * Module:  library/ecdh.c
 * Caller:  library/psa_crypto.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * This module is used by the following key exchanges:
 *      ECDHE-ECDSA, ECDHE-RSA, DHE-PSK
 *
 * Requires: MBEDTLS_ECP_C
 */
#define MBEDTLS_ECDH_C

/**
 * \def MBEDTLS_ECP_C
 *
 * Enable the elliptic curve over GF(p) library.
 *
 * Module:  library/ecp.c
 * Caller:  library/ecdh.c
 *          library/ecdsa.c
 *          library/ecjpake.c
 *
 * Requires: MBEDTLS_BIGNUM_C and at least one MBEDTLS_ECP_DP_XXX_ENABLED
 */
#define MBEDTLS_ECP_C

/**
 * \def MBEDTLS_ECP_DP_SECP192R1_ENABLED
 *
 * MBEDTLS_ECP_XXXX_ENABLED: Enables specific curves within the Elliptic Curve
 * module.  By default all supported curves are enabled.
 *
 * Comment macros to disable the curve and functions for it
 */
/* Short Weierstrass curves (supporting ECP, ECDH, ECDSA) */
#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_ECP_DP_SECP192K1_ENABLED
#define MBEDTLS_ECP_DP_SECP224K1_ENABLED
#define MBEDTLS_ECP_DP_SECP256K1_ENABLED
#define MBEDTLS_ECP_DP_BP256R1_ENABLED
#define MBEDTLS_ECP_DP_BP384R1_ENABLED
#define MBEDTLS_ECP_DP_BP512R1_ENABLED
/* Montgomery curves (supporting ECP) */
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECP_DP_CURVE448_ENABLED

/**
 * \def MBEDTLS_ECDSA_C
 *
 * Enable the elliptic curve DSA library.
 *
 * Module:  library/ecdsa.c
 * Caller:
 *
 * This module is used by the following key exchanges:
 *      ECDHE-ECDSA
 *
 * Requires: MBEDTLS_ECP_C, MBEDTLS_ASN1_WRITE_C, MBEDTLS_ASN1_PARSE_C,
 *           and at least one MBEDTLS_ECP_DP_XXX_ENABLED for a
 *           short Weierstrass curve.
 */
#define MBEDTLS_ECDSA_C

/**
 * \def MBEDTLS_ECDSA_DETERMINISTIC
 *
 * Enable deterministic ECDSA (RFC 6979).
 * Standard ECDSA is "fragile" in the sense that lack of entropy when signing
 * may result in a compromise of the long-term signing key. This is avoided by
 * the deterministic variant.
 *
 * Requires: MBEDTLS_HMAC_DRBG_C, MBEDTLS_ECDSA_C
 *
 * Comment this macro to disable deterministic ECDSA.
 */
#define MBEDTLS_ECDSA_DETERMINISTIC

/**
 * \def MBEDTLS_ECJPAKE_C
 *
 * Enable the elliptic curve J-PAKE library.
 *
 * \note EC J-PAKE support is based on the Thread v1.0.0 specification.
 *       It has not been reviewed for compliance with newer standards such as
 *       Thread v1.1 or RFC 8236.
 *
 * Module:  library/ecjpake.c
 * Caller:
 *
 * This module is used by the following key exchanges:
 *      ECJPAKE
 *
 * Requires: MBEDTLS_ECP_C and either MBEDTLS_MD_C or MBEDTLS_PSA_CRYPTO_C
 *
 * \warning If using a hash that is only provided by PSA drivers, you must
 * call psa_crypto_init() before doing any EC J-PAKE operations.
 */
#define MBEDTLS_ECJPAKE_C

/**
 * \def MBEDTLS_GCM_C
 *
 * Enable the Galois/Counter Mode (GCM).
 *
 * Module:  library/gcm.c
 *
 * Requires: MBEDTLS_CIPHER_C, MBEDTLS_AES_C or MBEDTLS_CAMELLIA_C or
 *                             MBEDTLS_ARIA_C
 *
 * This module enables the AES-GCM and CAMELLIA-GCM ciphersuites, if other
 * requisites are enabled as well.
 */
#define MBEDTLS_GCM_C

/**
 * \def MBEDTLS_GENPRIME
 *
 * Enable the prime-number generation code.
 *
 * Requires: MBEDTLS_BIGNUM_C
 */
#define MBEDTLS_GENPRIME

/**
 * \def MBEDTLS_HKDF_C
 *
 * Enable the HKDF algorithm (RFC 5869).
 *
 * Module:  library/hkdf.c
 * Caller:
 *
 * Requires: MBEDTLS_MD_C
 *
 * This module adds support for the Hashed Message Authentication Code
 * (HMAC)-based key derivation function (HKDF).
 */
#define MBEDTLS_HKDF_C

/**
 * \def MBEDTLS_HMAC_DRBG_C
 *
 * Enable the HMAC_DRBG random generator.
 *
 * Module:  library/hmac_drbg.c
 * Caller:
 *
 * Requires: MBEDTLS_MD_C
 *
 * Uncomment to enable the HMAC_DRBG random number generator.
 */
#define MBEDTLS_HMAC_DRBG_C

/**
 * \def MBEDTLS_MD5_C
 *
 * Enable the MD5 hash algorithm.
 *
 * Module:  library/md5.c
 * Caller:  library/md.c
 *          library/pem.c
 *          library/ssl_tls.c
 *
 * This module is required for TLS 1.2 depending on the handshake parameters.
 * Further, it is used for checking MD5-signed certificates, and for PBKDF1
 * when decrypting PEM-encoded encrypted keys.
 *
 * \warning   MD5 is considered a weak message digest and its use constitutes a
 *            security risk. If possible, we recommend avoiding dependencies on
 *            it, and considering stronger message digests instead.
 *
 */
#define MBEDTLS_MD5_C

/**
 * \def MBEDTLS_PKCS1_V15
 *
 * Enable support for PKCS#1 v1.5 encoding.
 *
 * Requires: MBEDTLS_RSA_C
 *
 * This enables support for PKCS#1 v1.5 operations.
 */
#define MBEDTLS_PKCS1_V15

/**
 * \def MBEDTLS_PKCS1_V21
 *
 * Enable support for PKCS#1 v2.1 encoding.
 *
 * Requires: MBEDTLS_RSA_C
 *
 * \warning If using a hash that is only provided by PSA drivers, you must
 * call psa_crypto_init() before doing any PKCS#1 v2.1 operation.
 *
 * This enables support for RSAES-OAEP and RSASSA-PSS operations.
 */
#define MBEDTLS_PKCS1_V21

/**
 * \def MBEDTLS_POLY1305_C
 *
 * Enable the Poly1305 MAC algorithm.
 *
 * Module:  library/poly1305.c
 * Caller:  library/chachapoly.c
 */
#define MBEDTLS_POLY1305_C

/**
 * \def MBEDTLS_PSA_CRYPTO_SE_C
 *
 * Enable dynamic secure element support in the Platform Security Architecture
 * cryptography API.
 *
 * \deprecated This feature is deprecated. Please switch to the PSA driver
 *             interface.
 *
 * \warning    This feature is not thread-safe, and should not be used in a
 *             multi-threaded environment.
 *
 * Module:  library/psa_crypto_se.c
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C, MBEDTLS_PSA_CRYPTO_STORAGE_C
 *
 */
//#define MBEDTLS_PSA_CRYPTO_SE_C

/**
 * \def MBEDTLS_RIPEMD160_C
 *
 * Enable the RIPEMD-160 hash algorithm.
 *
 * Module:  library/ripemd160.c
 * Caller:  library/md.c
 *
 */
#define MBEDTLS_RIPEMD160_C

/**
 * \def MBEDTLS_RSA_C
 *
 * Enable the RSA public-key cryptosystem.
 *
 * Module:  library/rsa.c
 *          library/rsa_alt_helpers.c
 * Caller:  library/pk.c
 *          library/psa_crypto.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * This module is used by the following key exchanges:
 *      RSA, DHE-RSA, ECDHE-RSA
 *
 * Requires: MBEDTLS_BIGNUM_C, MBEDTLS_OID_C
 */
#define MBEDTLS_RSA_C

/**
 * \def MBEDTLS_SHA1_C
 *
 * Enable the SHA1 cryptographic hash algorithm.
 *
 * Module:  library/sha1.c
 * Caller:  library/md.c
 *          library/psa_crypto_hash.c
 *
 * This module is required for TLS 1.2 depending on the handshake parameters,
 * and for SHA1-signed certificates.
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes
 *            a security risk. If possible, we recommend avoiding dependencies
 *            on it, and considering stronger message digests instead.
 *
 */
#define MBEDTLS_SHA1_C

/**
 * \def MBEDTLS_SHA224_C
 *
 * Enable the SHA-224 cryptographic hash algorithm.
 *
 * Module:  library/sha256.c
 * Caller:  library/md.c
 *          library/ssl_cookie.c
 *
 * This module adds support for SHA-224.
 */
#define MBEDTLS_SHA224_C

/**
 * \def MBEDTLS_SHA256_C
 *
 * Enable the SHA-256 cryptographic hash algorithm.
 *
 * Module:  library/sha256.c
 * Caller:  library/entropy.c
 *          library/md.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * This module adds support for SHA-256.
 * This module is required for the SSL/TLS 1.2 PRF function.
 */
#define MBEDTLS_SHA256_C

/**
 * \def MBEDTLS_SHA384_C
 *
 * Enable the SHA-384 cryptographic hash algorithm.
 *
 * Module:  library/sha512.c
 * Caller:  library/md.c
 *          library/psa_crypto_hash.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * Comment to disable SHA-384
 */
#define MBEDTLS_SHA384_C

/**
 * \def MBEDTLS_SHA512_C
 *
 * Enable SHA-512 cryptographic hash algorithms.
 *
 * Module:  library/sha512.c
 * Caller:  library/entropy.c
 *          library/md.c
 *          library/ssl_tls.c
 *          library/ssl_cookie.c
 *
 * This module adds support for SHA-512.
 */
#define MBEDTLS_SHA512_C

/**
 * \def MBEDTLS_SHA3_C
 *
 * Enable the SHA3 cryptographic hash algorithm.
 *
 * Module:  library/sha3.c
 *
 * This module adds support for SHA3.
 */
#define MBEDTLS_SHA3_C

/** \} name SECTION: Legacy cryptography */

#endif /* PSA_CRYPTO_CONFIG_H */
