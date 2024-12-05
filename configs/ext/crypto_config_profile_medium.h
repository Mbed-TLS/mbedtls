/*
 * Copyright (c) 2018-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
/**
 * \file psa/crypto_config.h
 * \brief PSA crypto configuration options (set of defines)
 *
 */

#ifndef PROFILE_M_PSA_CRYPTO_CONFIG_H
#define PROFILE_M_PSA_CRYPTO_CONFIG_H

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
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C

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
#define MBEDTLS_PLATFORM_MEMORY

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
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS

#define MBEDTLS_PLATFORM_PRINTF_ALT

/* To use the following function macros, MBEDTLS_PLATFORM_C must be enabled. */
/* MBEDTLS_PLATFORM_XXX_MACRO and MBEDTLS_PLATFORM_XXX_ALT cannot both be defined */

#include <stdio.h>

#define MBEDTLS_PLATFORM_SNPRINTF_MACRO    snprintf
#define MBEDTLS_PLATFORM_STD_EXIT_FAILURE  EXIT_FAILURE
#define MBEDTLS_PLATFORM_STD_EXIT_SUCCESS  EXIT_SUCCESS

#define MBEDTLS_PLATFORM_STD_MEM_HDR   <stdlib.h>

/** \} name SECTION: Platform abstraction layer */

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
//#define PSA_WANT_ALG_CBC_NO_PADDING             1
//#define PSA_WANT_ALG_CBC_PKCS7                  1
#define PSA_WANT_ALG_CCM                        1
//#define PSA_WANT_ALG_CMAC                       1
//#define PSA_WANT_ALG_CFB                        1
//#define PSA_WANT_ALG_CHACHA20_POLY1305          1
//#define PSA_WANT_ALG_CTR                        1
//#define PSA_WANT_ALG_DETERMINISTIC_ECDSA        1
//#define PSA_WANT_ALG_ECB_NO_PADDING             1
#define PSA_WANT_ALG_ECDH                       1
#define PSA_WANT_ALG_ECDSA                      1
//#define PSA_WANT_ALG_GCM                        1
#define PSA_WANT_ALG_HKDF                       1
#define PSA_WANT_ALG_HMAC                       1
//#define PSA_WANT_ALG_MD5                        1
//#define PSA_WANT_ALG_OFB                        1
/* PBKDF2-HMAC is not yet supported via the PSA API in Mbed TLS.
 * Note: when adding support, also adjust include/mbedtls/config_psa.h */
//#define PSA_WANT_ALG_PBKDF2_HMAC                1
//#define PSA_WANT_ALG_RIPEMD160                  1
//#define PSA_WANT_ALG_RSA_OAEP                   1
//#define PSA_WANT_ALG_RSA_PKCS1V15_CRYPT         1
//#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN          1
//#define PSA_WANT_ALG_RSA_PSS                    1
//#define PSA_WANT_ALG_SHA_1                      1
#define PSA_WANT_ALG_SHA_224                    1
#define PSA_WANT_ALG_SHA_256                    1
//#define PSA_WANT_ALG_SHA_384                    1
//#define PSA_WANT_ALG_SHA_512                    1
//#define PSA_WANT_ALG_STREAM_CIPHER              1
#define PSA_WANT_ALG_TLS12_PRF                  1
#define PSA_WANT_ALG_TLS12_PSK_TO_MS            1
/* PBKDF2-HMAC is not yet supported via the PSA API in Mbed TLS.
 * Note: when adding support, also adjust include/mbedtls/config_psa.h */
//#define PSA_WANT_ALG_XTS                        1

//#define PSA_WANT_ECC_BRAINPOOL_P_R1_256         1
//#define PSA_WANT_ECC_BRAINPOOL_P_R1_384         1
//#define PSA_WANT_ECC_BRAINPOOL_P_R1_512         1
//#define PSA_WANT_ECC_MONTGOMERY_255             1
//#define PSA_WANT_ECC_MONTGOMERY_448             1
//#define PSA_WANT_ECC_SECP_K1_192                1
/*
 * SECP224K1 is buggy via the PSA API in Mbed TLS
 * (https://github.com/Mbed-TLS/mbedtls/issues/3541). Thus, do not enable it by
 * default.
 */
//#define PSA_WANT_ECC_SECP_K1_224                1
//#define PSA_WANT_ECC_SECP_K1_256                1
//#define PSA_WANT_ECC_SECP_R1_192                1
//#define PSA_WANT_ECC_SECP_R1_224                1
#define PSA_WANT_ECC_SECP_R1_256                1
//#define PSA_WANT_ECC_SECP_R1_384                1
//#define PSA_WANT_ECC_SECP_R1_521                1

#define PSA_WANT_KEY_TYPE_DERIVE                1
#define PSA_WANT_KEY_TYPE_HMAC                  1
#define PSA_WANT_KEY_TYPE_AES                   1
//#define PSA_WANT_KEY_TYPE_ARIA                  1
//#define PSA_WANT_KEY_TYPE_CAMELLIA              1
//#define PSA_WANT_KEY_TYPE_CHACHA20              1
//#define PSA_WANT_KEY_TYPE_DES                   1
//#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR          1 /* Deprecated */
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_RAW_DATA              1
//#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR          1 /* Deprecated */
//#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY        1

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
//#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE   1

/** \} name SECTION Cryptographic mechanism selection (PSA API) */

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
#define MBEDTLS_ENTROPY_NV_SEED

/**
 * \def MBEDTLS_NO_PLATFORM_ENTROPY
 *
 * Do not use built-in platform entropy functions.
 * This is useful if your platform does not support
 * standards like the /dev/urandom or Windows CryptoAPI.
 *
 * Uncomment this macro to disable the built-in platform entropy functions.
 */
#define MBEDTLS_NO_PLATFORM_ENTROPY

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
#define MBEDTLS_PSA_CRYPTO_SPM

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

/** \} name SECTION: PSA core */

/**
 * \name SECTION: Builtin drivers
 *
 * This section sets driver specific settings.
 * \{
 */

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
#define MBEDTLS_AES_ROM_TABLES

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
#define MBEDTLS_AES_FEWER_TABLES

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
#define MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH

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
#define MBEDTLS_PSA_P256M_DRIVER_ENABLED

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
#define MBEDTLS_SHA256_SMALLER

/* ECP options */
#define MBEDTLS_ECP_FIXED_POINT_OPTIM        0 /**< Disable fixed-point speed-up */

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
/** \} name SECTION: Legacy cryptography */

/***********************************************************/
/* Tweak the configuration to remove dependencies on TF-M. */
/***********************************************************/

/* MBEDTLS_PSA_CRYPTO_SPM needs third-party files, so disable it. */
#undef MBEDTLS_PSA_CRYPTO_SPM

/* Disable buffer-based memory allocator. This isn't strictly required,
 * but using the native allocator is faster and works better with
 * memory management analysis frameworks such as ASan. */
#undef MBEDTLS_MEMORY_BUFFER_ALLOC_C

// This macro is enabled in TFM Medium but is disabled here because it is
// incompatible with baremetal builds in Mbed TLS.
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C

// This macro is enabled in TFM Medium but is disabled here because it is
// incompatible with baremetal builds in Mbed TLS.
#undef MBEDTLS_ENTROPY_NV_SEED

// These platform-related TF-M settings are not useful here.
#undef MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#undef MBEDTLS_PLATFORM_STD_MEM_HDR
#undef MBEDTLS_PLATFORM_SNPRINTF_MACRO
#undef MBEDTLS_PLATFORM_PRINTF_ALT
#undef MBEDTLS_PLATFORM_STD_EXIT_SUCCESS
#undef MBEDTLS_PLATFORM_STD_EXIT_FAILURE

/*
 * In order to get an example config that works cleanly out-of-the-box
 * for both baremetal and non-baremetal builds, we detect baremetal builds
 * (either IAR, Arm compiler or __ARM_EABI__ defined), and adjust some
 * variables accordingly.
 */
#if defined(__IAR_SYSTEMS_ICC__) || defined(__ARMCC_VERSION) || defined(__ARM_EABI__)
#define MBEDTLS_NO_PLATFORM_ENTROPY
#else
/* Use built-in platform entropy functions (TF-M provides its own). */
#undef MBEDTLS_NO_PLATFORM_ENTROPY
#endif

/***********************************************************************
 * Local changes to crypto config below this delimiter
 **********************************************************************/

// We expect TF-M to pick this up soon
#define MBEDTLS_BLOCK_CIPHER_NO_DECRYPT

/* CCM is the only cipher/AEAD enabled in TF-M configuration files, but it
 * does not need CIPHER_C to be enabled, so we can disable it in order
 * to reduce code size further. */
#undef MBEDTLS_CIPHER_C

#if CRYPTO_NV_SEED
#include "tfm_mbedcrypto_config_extra_nv_seed.h"
#endif /* CRYPTO_NV_SEED */

#if !defined(CRYPTO_HW_ACCELERATOR) && defined(MBEDTLS_ENTROPY_NV_SEED)
#include "mbedtls_entropy_nv_seed_config.h"
#endif

#ifdef CRYPTO_HW_ACCELERATOR
#include "crypto_accelerator_config.h"
#endif

#endif /* PROFILE_M_PSA_CRYPTO_CONFIG_H */
