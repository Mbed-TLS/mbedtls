/**
 * \file config.h
 *
 * \brief Configuration options (set of defines)
 *
 *  This set of compile-time options may be used to enable
 *  or disable features selectively, and reduce the global
 *  memory footprint.
 */
/*
 *  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

/**
 * \name SECTION: System support
 *
 * This section sets system specific settings.
 * \{
 */

/**
 * \def MBEDTLS_HAVE_ASM
 *
 * The compiler has support for asm().
 *
 * Requires support for asm() in compiler.
 *
 * Used in:
 *      library/aria.c
 *      library/timing.c
 *      include/mbedtls/bn_mul.h
 *
 * Required by:
 *      MBEDTLS_AESNI_C
 *      MBEDTLS_PADLOCK_C
 *
 * Comment to disable the use of assembly code.
 */
#define MBEDTLS_HAVE_ASM

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
 * \def MBEDTLS_HAVE_SSE2
 *
 * CPU supports SSE2 instruction set.
 *
 * Uncomment if the CPU supports SSE2 (IA-32 specific).
 */
//#define MBEDTLS_HAVE_SSE2

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
 * Comment if your system does not support time functions
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
 * \def MBEDTLS_PLATFORM_MEMORY
 *
 * Enable the memory allocation layer.
 *
 * By default mbed TLS uses the system-provided calloc() and free().
 * This allows different allocators (self-implemented or provided) to be
 * provided to the platform abstraction layer.
 *
 * Enabling MBEDTLS_PLATFORM_MEMORY without the
 * MBEDTLS_PLATFORM_{FREE,CALLOC}_MACROs will provide
 * "mbedtls_platform_set_calloc_free()" allowing you to set an alternative calloc() and
 * free() function pointer at runtime.
 *
 * Enabling MBEDTLS_PLATFORM_MEMORY and specifying
 * MBEDTLS_PLATFORM_{CALLOC,FREE}_MACROs will allow you to specify the
 * alternate function at compile time.
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
 * \def MBEDTLS_PLATFORM_EXIT_ALT
 *
 * MBEDTLS_PLATFORM_XXX_ALT: Uncomment a macro to let mbed TLS support the
 * function in the platform abstraction layer.
 *
 * Example: In case you uncomment MBEDTLS_PLATFORM_PRINTF_ALT, mbed TLS will
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
//#define MBEDTLS_PLATFORM_EXIT_ALT
//#define MBEDTLS_PLATFORM_TIME_ALT
//#define MBEDTLS_PLATFORM_FPRINTF_ALT
//#define MBEDTLS_PLATFORM_PRINTF_ALT
//#define MBEDTLS_PLATFORM_SNPRINTF_ALT
//#define MBEDTLS_PLATFORM_VSNPRINTF_ALT
//#define MBEDTLS_PLATFORM_NV_SEED_ALT
//#define MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT

/**
 * \def MBEDTLS_DEPRECATED_WARNING
 *
 * Mark deprecated functions so that they generate a warning if used.
 * Functions deprecated in one version will usually be removed in the next
 * version. You can enable this to help you prepare the transition to a new
 * major version by making sure your code is not using these functions.
 *
 * This only works with GCC and Clang. With other compilers, you may want to
 * use MBEDTLS_DEPRECATED_REMOVED
 *
 * Uncomment to get warnings on using deprecated functions.
 */
//#define MBEDTLS_DEPRECATED_WARNING

/**
 * \def MBEDTLS_DEPRECATED_REMOVED
 *
 * Remove deprecated functions so that they generate an error if used.
 * Functions deprecated in one version will usually be removed in the next
 * version. You can enable this to help you prepare the transition to a new
 * major version by making sure your code is not using these functions.
 *
 * Uncomment to get errors on using deprecated functions.
 */
//#define MBEDTLS_DEPRECATED_REMOVED

/**
 * \def MBEDTLS_CHECK_PARAMS
 *
 * This configuration option controls whether the library validates more of
 * the parameters passed to it.
 *
 * When this flag is not defined, the library only attempts to validate an
 * input parameter if: (1) they may come from the outside world (such as the
 * network, the filesystem, etc.) or (2) not validating them could result in
 * internal memory errors such as overflowing a buffer controlled by the
 * library. On the other hand, it doesn't attempt to validate parameters whose
 * values are fully controlled by the application (such as pointers).
 *
 * When this flag is defined, the library additionally attempts to validate
 * parameters that are fully controlled by the application, and should always
 * be valid if the application code is fully correct and trusted.
 *
 * For example, when a function accepts as input a pointer to a buffer that may
 * contain untrusted data, and its documentation mentions that this pointer
 * must not be NULL:
 * - the pointer is checked to be non-NULL only if this option is enabled
 * - the content of the buffer is always validated
 *
 * When this flag is defined, if a library function receives a parameter that
 * is invalid, it will:
 * - invoke the macro MBEDTLS_PARAM_FAILED() which by default expands to a
 *   call to the function mbedtls_param_failed()
 * - immediately return (with a specific error code unless the function
 *   returns void and can't communicate an error).
 *
 * When defining this flag, you also need to:
 * - either provide a definition of the function mbedtls_param_failed() in
 *   your application (see platform_util.h for its prototype) as the library
 *   calls that function, but does not provide a default definition for it,
 * - or provide a different definition of the macro MBEDTLS_PARAM_FAILED()
 *   below if the above mechanism is not flexible enough to suit your needs.
 *   See the documentation of this macro later in this file.
 *
 * Uncomment to enable validation of application-controlled parameters.
 */
//#define MBEDTLS_CHECK_PARAMS

/* \} name SECTION: System support */

/**
 * \name SECTION: mbed TLS feature support
 *
 * This section sets support for features that are or are not needed
 * within the modules that are enabled.
 * \{
 */

/**
 * \def MBEDTLS_TIMING_ALT
 *
 * Uncomment to provide your own alternate implementation for mbedtls_timing_hardclock(),
 * mbedtls_timing_get_timer(), mbedtls_set_alarm(), mbedtls_set/get_delay()
 *
 * Only works if you have MBEDTLS_TIMING_C enabled.
 *
 * You will need to provide a header "timing_alt.h" and an implementation at
 * compile time.
 */
//#define MBEDTLS_TIMING_ALT

/**
 * \def MBEDTLS_AES_ALT
 *
 * MBEDTLS__MODULE_NAME__ALT: Uncomment a macro to let mbed TLS use your
 * alternate core implementation of a symmetric crypto, an arithmetic or hash
 * module (e.g. platform specific assembly optimized implementations). Keep
 * in mind that the function prototypes should remain the same.
 *
 * This replaces the whole module. If you only want to replace one of the
 * functions, use one of the MBEDTLS__FUNCTION_NAME__ALT flags.
 *
 * Example: In case you uncomment MBEDTLS_AES_ALT, mbed TLS will no longer
 * provide the "struct mbedtls_aes_context" definition and omit the base
 * function declarations and implementations. "aes_alt.h" will be included from
 * "aes.h" to include the new function definitions.
 *
 * Uncomment a macro to enable alternate implementation of the corresponding
 * module.
 *
 * \warning   MD2, MD4, MD5, ARC4, DES and SHA-1 are considered weak and their
 *            use constitutes a security risk. If possible, we recommend
 *            avoiding dependencies on them, and considering stronger message
 *            digests and ciphers instead.
 *
 */
//#define MBEDTLS_AES_ALT
//#define MBEDTLS_ARC4_ALT
//#define MBEDTLS_ARIA_ALT
//#define MBEDTLS_BLOWFISH_ALT
//#define MBEDTLS_CAMELLIA_ALT
//#define MBEDTLS_CCM_ALT
//#define MBEDTLS_CHACHA20_ALT
//#define MBEDTLS_CHACHAPOLY_ALT
//#define MBEDTLS_CMAC_ALT
//#define MBEDTLS_DES_ALT
//#define MBEDTLS_DHM_ALT
//#define MBEDTLS_ECJPAKE_ALT
//#define MBEDTLS_GCM_ALT
//#define MBEDTLS_NIST_KW_ALT
//#define MBEDTLS_MD2_ALT
//#define MBEDTLS_MD4_ALT
//#define MBEDTLS_MD5_ALT
//#define MBEDTLS_POLY1305_ALT
//#define MBEDTLS_RIPEMD160_ALT
//#define MBEDTLS_RSA_ALT
//#define MBEDTLS_SHA1_ALT
//#define MBEDTLS_SHA256_ALT
//#define MBEDTLS_SHA512_ALT
//#define MBEDTLS_XTEA_ALT

/*
 * When replacing the elliptic curve module, pleace consider, that it is
 * implemented with two .c files:
 *      - ecp.c
 *      - ecp_curves.c
 * You can replace them very much like all the other MBEDTLS__MODULE_NAME__ALT
 * macros as described above. The only difference is that you have to make sure
 * that you provide functionality for both .c files.
 */
//#define MBEDTLS_ECP_ALT

/**
 * \def MBEDTLS_MD2_PROCESS_ALT
 *
 * MBEDTLS__FUNCTION_NAME__ALT: Uncomment a macro to let mbed TLS use you
 * alternate core implementation of symmetric crypto or hash function. Keep in
 * mind that function prototypes should remain the same.
 *
 * This replaces only one function. The header file from mbed TLS is still
 * used, in contrast to the MBEDTLS__MODULE_NAME__ALT flags.
 *
 * Example: In case you uncomment MBEDTLS_SHA256_PROCESS_ALT, mbed TLS will
 * no longer provide the mbedtls_sha1_process() function, but it will still provide
 * the other function (using your mbedtls_sha1_process() function) and the definition
 * of mbedtls_sha1_context, so your implementation of mbedtls_sha1_process must be compatible
 * with this definition.
 *
 * \note Because of a signature change, the core AES encryption and decryption routines are
 *       currently named mbedtls_aes_internal_encrypt and mbedtls_aes_internal_decrypt,
 *       respectively. When setting up alternative implementations, these functions should
 *       be overridden, but the wrapper functions mbedtls_aes_decrypt and mbedtls_aes_encrypt
 *       must stay untouched.
 *
 * \note If you use the AES_xxx_ALT macros, then is is recommended to also set
 *       MBEDTLS_AES_ROM_TABLES in order to help the linker garbage-collect the AES
 *       tables.
 *
 * Uncomment a macro to enable alternate implementation of the corresponding
 * function.
 *
 * \warning   MD2, MD4, MD5, DES and SHA-1 are considered weak and their use
 *            constitutes a security risk. If possible, we recommend avoiding
 *            dependencies on them, and considering stronger message digests
 *            and ciphers instead.
 *
 */
//#define MBEDTLS_MD2_PROCESS_ALT
//#define MBEDTLS_MD4_PROCESS_ALT
//#define MBEDTLS_MD5_PROCESS_ALT
//#define MBEDTLS_RIPEMD160_PROCESS_ALT
//#define MBEDTLS_SHA1_PROCESS_ALT
//#define MBEDTLS_SHA256_PROCESS_ALT
//#define MBEDTLS_SHA512_PROCESS_ALT
//#define MBEDTLS_DES_SETKEY_ALT
//#define MBEDTLS_DES_CRYPT_ECB_ALT
//#define MBEDTLS_DES3_CRYPT_ECB_ALT
//#define MBEDTLS_AES_SETKEY_ENC_ALT
//#define MBEDTLS_AES_SETKEY_DEC_ALT
//#define MBEDTLS_AES_ENCRYPT_ALT
//#define MBEDTLS_AES_DECRYPT_ALT
//#define MBEDTLS_ECDH_GEN_PUBLIC_ALT
//#define MBEDTLS_ECDH_COMPUTE_SHARED_ALT
//#define MBEDTLS_ECDSA_VERIFY_ALT
//#define MBEDTLS_ECDSA_SIGN_ALT
//#define MBEDTLS_ECDSA_GENKEY_ALT

/**
 * \def MBEDTLS_ECP_INTERNAL_ALT
 *
 * Expose a part of the internal interface of the Elliptic Curve Point module.
 *
 * MBEDTLS_ECP__FUNCTION_NAME__ALT: Uncomment a macro to let mbed TLS use your
 * alternative core implementation of elliptic curve arithmetic. Keep in mind
 * that function prototypes should remain the same.
 *
 * This partially replaces one function. The header file from mbed TLS is still
 * used, in contrast to the MBEDTLS_ECP_ALT flag. The original implementation
 * is still present and it is used for group structures not supported by the
 * alternative.
 *
 * Any of these options become available by defining MBEDTLS_ECP_INTERNAL_ALT
 * and implementing the following functions:
 *      unsigned char mbedtls_internal_ecp_grp_capable(
 *          const mbedtls_ecp_group *grp )
 *      int  mbedtls_internal_ecp_init( const mbedtls_ecp_group *grp )
 *      void mbedtls_internal_ecp_free( const mbedtls_ecp_group *grp )
 * The mbedtls_internal_ecp_grp_capable function should return 1 if the
 * replacement functions implement arithmetic for the given group and 0
 * otherwise.
 * The functions mbedtls_internal_ecp_init and mbedtls_internal_ecp_free are
 * called before and after each point operation and provide an opportunity to
 * implement optimized set up and tear down instructions.
 *
 * Example: In case you uncomment MBEDTLS_ECP_INTERNAL_ALT and
 * MBEDTLS_ECP_DOUBLE_JAC_ALT, mbed TLS will still provide the ecp_double_jac
 * function, but will use your mbedtls_internal_ecp_double_jac if the group is
 * supported (your mbedtls_internal_ecp_grp_capable function returns 1 when
 * receives it as an argument). If the group is not supported then the original
 * implementation is used. The other functions and the definition of
 * mbedtls_ecp_group and mbedtls_ecp_point will not change, so your
 * implementation of mbedtls_internal_ecp_double_jac and
 * mbedtls_internal_ecp_grp_capable must be compatible with this definition.
 *
 * Uncomment a macro to enable alternate implementation of the corresponding
 * function.
 */
/* Required for all the functions in this section */
//#define MBEDTLS_ECP_INTERNAL_ALT
/* Support for Weierstrass curves with Jacobi representation */
//#define MBEDTLS_ECP_RANDOMIZE_JAC_ALT
//#define MBEDTLS_ECP_ADD_MIXED_ALT
//#define MBEDTLS_ECP_DOUBLE_JAC_ALT
//#define MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT
//#define MBEDTLS_ECP_NORMALIZE_JAC_ALT
/* Support for curves with Montgomery arithmetic */
//#define MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT
//#define MBEDTLS_ECP_RANDOMIZE_MXZ_ALT
//#define MBEDTLS_ECP_NORMALIZE_MXZ_ALT

/**
 * \def MBEDTLS_TEST_NULL_ENTROPY
 *
 * Enables testing and use of mbed TLS without any configured entropy sources.
 * This permits use of the library on platforms before an entropy source has
 * been integrated (see for example the MBEDTLS_ENTROPY_HARDWARE_ALT or the
 * MBEDTLS_ENTROPY_NV_SEED switches).
 *
 * WARNING! This switch MUST be disabled in production builds, and is suitable
 * only for development.
 * Enabling the switch negates any security provided by the library.
 *
 * Requires MBEDTLS_ENTROPY_C, MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
 *
 */
//#define MBEDTLS_TEST_NULL_ENTROPY

/**
 * \def MBEDTLS_ENTROPY_HARDWARE_ALT
 *
 * Uncomment this macro to let mbed TLS use your own implementation of a
 * hardware entropy collector.
 *
 * Your function must be called \c mbedtls_hardware_poll(), have the same
 * prototype as declared in entropy_poll.h, and accept NULL as first argument.
 *
 * Uncomment to use your own hardware entropy collector.
 */
//#define MBEDTLS_ENTROPY_HARDWARE_ALT

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
 *
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
 *
 */
//#define MBEDTLS_AES_FEWER_TABLES

/**
 * \def MBEDTLS_CAMELLIA_SMALL_MEMORY
 *
 * Use less ROM for the Camellia implementation (saves about 768 bytes).
 *
 * Uncomment this macro to use less memory for Camellia.
 */
//#define MBEDTLS_CAMELLIA_SMALL_MEMORY

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
 * This module is required to support the TLS ciphersuites that use the NULL
 * cipher.
 *
 * Uncomment this macro to enable the NULL cipher
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
 * \def MBEDTLS_ECP_DP_SECP192R1_ENABLED
 *
 * MBEDTLS_ECP_XXXX_ENABLED: Enables specific curves within the Elliptic Curve
 * module.  By default all supported curves are enabled.
 *
 * Comment macros to disable the curve and functions for it
 */
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
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECP_DP_CURVE448_ENABLED

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
 * #MBEDTLS_ERR_ECP_IN_PROGRESS (or, for functions in Mbed TLS's SSL module,
 * MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) and then be called later again in order
 * to further progress and eventually complete their operation. This is
 * controlled through mbedtls_ecp_set_max_ops() which limits the maximum number
 * of ECC operations a function may perform before pausing; see
 * mbedtls_ecp_set_max_ops() for more information.
 *
 * This is useful in non-threaded environments if you want to avoid blocking
 * for too long on ECC (and, hence, X.509 or SSL/TLS) operations.
 *
 * Uncomment this macro to enable restartable ECC computations.
 *
 * \note  This option only works with the default software implementation of
 *        elliptic curve functionality. It is incompatible with
 *        MBEDTLS_ECP_ALT, MBEDTLS_ECDH_XXX_ALT and MBEDTLS_ECDSA_XXX_ALT.
 */
//#define MBEDTLS_ECP_RESTARTABLE

/**
 * \def MBEDTLS_ECDSA_DETERMINISTIC
 *
 * Enable deterministic ECDSA (RFC 6979).
 * Standard ECDSA is "fragile" in the sense that lack of entropy when signing
 * may result in a compromise of the long-term signing key. This is avoided by
 * the deterministic variant.
 *
 * Requires: MBEDTLS_HMAC_DRBG_C
 *
 * Comment this macro to disable deterministic ECDSA.
 */
#define MBEDTLS_ECDSA_DETERMINISTIC

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
 * \def MBEDTLS_ERROR_STRERROR_DUMMY
 *
 * Enable a dummy error function to make use of mbedtls_strerror() in
 * third party libraries easier when MBEDTLS_ERROR_C is disabled
 * (no effect when MBEDTLS_ERROR_C is enabled).
 *
 * You can safely disable this if MBEDTLS_ERROR_C is enabled, or if you're
 * not using mbedtls_strerror() or error_strerror() in your application.
 *
 * Disable if you run into name conflicts and want to really remove the
 * mbedtls_strerror()
 */
#define MBEDTLS_ERROR_STRERROR_DUMMY

/**
 * \def MBEDTLS_GENPRIME
 *
 * Enable the prime-number generation code.
 *
 * Requires: MBEDTLS_BIGNUM_C
 */
#define MBEDTLS_GENPRIME

/**
 * \def MBEDTLS_FS_IO
 *
 * Enable functions that use the filesystem.
 */
#define MBEDTLS_FS_IO

/**
 * \def MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
 *
 * Do not add default entropy sources. These are the platform specific,
 * mbedtls_timing_hardclock and HAVEGE based poll functions.
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

/* MBEDTLS_PSA_CRYPTO_KEY_FILE_ID_ENCODES_OWNER
 *
 * In PSA key storage, encode the owner of the key.
 *
 * This is only meaningful when building the library as part of a
 * multi-client service. When you activate this option, you must provide
 * an implementation of the type psa_key_owner_id_t and a translation
 * from psa_key_file_id_t to file name in all the storage backends that
 * you wish to support.
 *
 * Note that this option is meant for internal use only and may be removed
 * without notice.
 */
//#define MBEDTLS_PSA_CRYPTO_KEY_FILE_ID_ENCODES_OWNER

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
 *           GLIBC-compatible backtrace() an backtrace_symbols() support
 *
 * Uncomment this macro to include backtrace information
 */
//#define MBEDTLS_MEMORY_BACKTRACE

/**
 * \def MBEDTLS_PK_RSA_ALT_SUPPORT
 *
 * Support external private RSA keys (eg from a HSM) in the PK layer.
 *
 * Comment this macro to disable support for external private RSA keys.
 */
#define MBEDTLS_PK_RSA_ALT_SUPPORT

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
 * Requires: MBEDTLS_MD_C, MBEDTLS_RSA_C
 *
 * This enables support for RSAES-OAEP and RSASSA-PSS operations.
 */
#define MBEDTLS_PKCS1_V21

/**
 * \def MBEDTLS_PSA_CRYPTO_SPM
 *
 * When MBEDTLS_PSA_CRYPTO_SPM is defined, the code is built for SPM (Secure
 * Partition Manager) integration which separates the code into two parts: a
 * NSPE (Non-Secure Process Environment) and an SPE (Secure Process
 * Environment).
 *
 * Module:  library/psa_crypto.c
 * Requires: MBEDTLS_PSA_CRYPTO_C
 *
 */
//#define MBEDTLS_PSA_CRYPTO_SPM

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
 * \def MBEDTLS_SELF_TEST
 *
 * Enable the checkup functions (*_self_test).
 */
#define MBEDTLS_SELF_TEST

/**
 * \def MBEDTLS_SHA256_SMALLER
 *
 * Enable an implementation of SHA-256 that has lower ROM footprint but also
 * lower performance.
 *
 * The default implementation is meant to be a reasonnable compromise between
 * performance and size. This version optimizes more aggressively for size at
 * the expense of performance. Eg on Cortex-M4 it reduces the size of
 * mbedtls_sha256_process() from ~2KB to ~0.5KB for a performance hit of about
 * 30%.
 *
 * Uncomment to enable the smaller implementation of SHA256.
 */
//#define MBEDTLS_SHA256_SMALLER

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
 * \def MBEDTLS_USE_PSA_CRYPTO
 *
 * Make the X.509 and TLS library use PSA for cryptographic operations, see
 * #MBEDTLS_PSA_CRYPTO_C.
 *
 * Note: this option is still in progress, the full X.509 and TLS modules are
 * not covered yet, but parts that are not ported to PSA yet will still work
 * as usual, so enabling this option should not break backwards compatibility.
 *
 * \warning  Support for PSA is still an experimental feature.
 *           Any public API that depends on this option may change
 *           at any time until this warning is removed.
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C.
 */
//#define MBEDTLS_USE_PSA_CRYPTO

/**
 * \def MBEDTLS_VERSION_FEATURES
 *
 * Allow run-time checking of compile-time enabled features. Thus allowing users
 * to check at run-time if the library is for instance compiled with threading
 * support via mbedtls_version_check_feature().
 *
 * Requires: MBEDTLS_VERSION_C
 *
 * Comment this to disable run-time checking and save ROM space
 */
#define MBEDTLS_VERSION_FEATURES

/* \} name SECTION: mbed TLS feature support */

/**
 * \name SECTION: mbed TLS modules
 *
 * This section enables or disables entire modules in mbed TLS
 * \{
 */

/**
 * \def MBEDTLS_AESNI_C
 *
 * Enable AES-NI support on x86-64.
 *
 * Module:  library/aesni.c
 * Caller:  library/aes.c
 *
 * Requires: MBEDTLS_HAVE_ASM
 *
 * This modules adds support for the AES-NI instructions on x86-64
 */
#define MBEDTLS_AESNI_C

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
 * This module is required to support the TLS ciphersuites that use the AES
 * cipher.
 *
 * PEM_PARSE uses AES for decrypting encrypted keys.
 */
#define MBEDTLS_AES_C

/**
 * \def MBEDTLS_ARC4_C
 *
 * Enable the ARCFOUR stream cipher.
 *
 * Module:  library/arc4.c
 * Caller:  library/cipher.c
 *
 * This module is required to support the TLS ciphersuites that use the ARC4
 * cipher.
 *
 * \warning   ARC4 is considered a weak cipher and its use constitutes a
 *            security risk. If possible, we recommend avoidng dependencies on
 *            it, and considering stronger ciphers instead.
 *
 */
#define MBEDTLS_ARC4_C

/**
 * \def MBEDTLS_ASN1_PARSE_C
 *
 * Enable the generic ASN1 parser.
 *
 * Module:  library/asn1.c
 * Caller:  library/dhm.c
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
 * \def MBEDTLS_BIGNUM_C
 *
 * Enable the multi-precision integer library.
 *
 * Module:  library/bignum.c
 * Caller:  library/dhm.c
 *          library/ecp.c
 *          library/ecdsa.c
 *          library/rsa.c
 *          library/rsa_internal.c
 *
 * This module is required for RSA, DHM and ECC (ECDH, ECDSA) support.
 */
#define MBEDTLS_BIGNUM_C

/**
 * \def MBEDTLS_BLOWFISH_C
 *
 * Enable the Blowfish block cipher.
 *
 * Module:  library/blowfish.c
 */
#define MBEDTLS_BLOWFISH_C

/**
 * \def MBEDTLS_CAMELLIA_C
 *
 * Enable the Camellia block cipher.
 *
 * Module:  library/camellia.c
 * Caller:  library/cipher.c
 *
 * This module is required to support the TLS ciphersuites that use the
 * Camellia cipher.
 */
#define MBEDTLS_CAMELLIA_C

/**
 * \def MBEDTLS_ARIA_C
 *
 * Enable the ARIA block cipher.
 *
 * Module:  library/aria.c
 * Caller:  library/cipher.c
 *
 * This module is required to support the TLS ciphersuites that use the
 * ARIA cipher.
 */
//#define MBEDTLS_ARIA_C

/**
 * \def MBEDTLS_CCM_C
 *
 * Enable the Counter with CBC-MAC (CCM) mode for 128-bit block cipher.
 *
 * Module:  library/ccm.c
 *
 * Requires: MBEDTLS_AES_C or MBEDTLS_CAMELLIA_C
 *
 * This module is required to support AES-CCM ciphersuites in TLS.
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
 *
 * Uncomment to enable generic cipher wrappers.
 */
#define MBEDTLS_CIPHER_C

/**
 * \def MBEDTLS_CMAC_C
 *
 * Enable the CMAC (Cipher-based Message Authentication Code) mode for block
 * ciphers.
 *
 * Module:  library/cmac.c
 *
 * Requires: MBEDTLS_AES_C or MBEDTLS_DES_C
 *
 */
#define MBEDTLS_CMAC_C

/**
 * \def MBEDTLS_CTR_DRBG_C
 *
 * Enable the CTR_DRBG AES-based random generator.
 * The CTR_DRBG generator uses AES-256 by default.
 * To use AES-128 instead, enable MBEDTLS_CTR_DRBG_USE_128_BIT_KEY below.
 *
 * Module:  library/ctr_drbg.c
 * Caller:
 *
 * Requires: MBEDTLS_AES_C
 *
 * This module provides the CTR_DRBG AES random number generator.
 */
#define MBEDTLS_CTR_DRBG_C

/**
 * \def MBEDTLS_DES_C
 *
 * Enable the DES block cipher.
 *
 * Module:  library/des.c
 * Caller:  library/pem.c
 *          library/cipher.c
 *
 * This module is required to support the TLS ciphersuites that use the DES
 * cipher.
 *
 * PEM_PARSE uses DES/3DES for decrypting encrypted keys.
 *
 * \warning   DES is considered a weak cipher and its use constitutes a
 *            security risk. We recommend considering stronger ciphers instead.
 */
#define MBEDTLS_DES_C

/**
 * \def MBEDTLS_DHM_C
 *
 * Enable the Diffie-Hellman-Merkle module.
 *
 * Module:  library/dhm.c
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
 *
 * This module is used by the following key exchanges:
 *      ECDHE-ECDSA, ECDHE-RSA, DHE-PSK
 *
 * Requires: MBEDTLS_ECP_C
 */
#define MBEDTLS_ECDH_C

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
 * Requires: MBEDTLS_ECP_C, MBEDTLS_ASN1_WRITE_C, MBEDTLS_ASN1_PARSE_C
 */
#define MBEDTLS_ECDSA_C

/**
 * \def MBEDTLS_ECJPAKE_C
 *
 * Enable the elliptic curve J-PAKE library.
 *
 * \warning This is currently experimental. EC J-PAKE support is based on the
 * Thread v1.0.0 specification; incompatible changes to the specification
 * might still happen. For this reason, this is disabled by default.
 *
 * Module:  library/ecjpake.c
 * Caller:
 *
 * This module is used by the following key exchanges:
 *      ECJPAKE
 *
 * Requires: MBEDTLS_ECP_C, MBEDTLS_MD_C
 */
//#define MBEDTLS_ECJPAKE_C

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
 * \def MBEDTLS_ERROR_C
 *
 * Enable error code to error string conversion.
 *
 * Module:  library/error.c
 * Caller:
 *
 * This module enables mbedtls_strerror().
 */
#define MBEDTLS_ERROR_C

/**
 * \def MBEDTLS_GCM_C
 *
 * Enable the Galois/Counter Mode (GCM) for AES.
 *
 * Module:  library/gcm.c
 *
 * Requires: MBEDTLS_AES_C or MBEDTLS_CAMELLIA_C
 *
 * This module is required to support the TLS ciphersuites that use GCM.
 */
#define MBEDTLS_GCM_C

/**
 * \def MBEDTLS_HAVEGE_C
 *
 * Enable the HAVEGE random generator.
 *
 * Warning: the HAVEGE random generator is not suitable for virtualized
 *          environments
 *
 * Warning: the HAVEGE random generator is dependent on timing and specific
 *          processor traits. It is therefore not advised to use HAVEGE as
 *          your applications primary random generator or primary entropy pool
 *          input. As a secondary input to your entropy pool, it IS able add
 *          the (limited) extra entropy it provides.
 *
 * Module:  library/havege.c
 * Caller:
 *
 * Requires: MBEDTLS_TIMING_C
 *
 * Uncomment to enable the HAVEGE random generator.
 */
//#define MBEDTLS_HAVEGE_C

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
 * Uncomment to enable the HMAC_DRBG random number geerator.
 */
#define MBEDTLS_HMAC_DRBG_C

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
//#define MBEDTLS_NIST_KW_C

/**
 * \def MBEDTLS_MD_C
 *
 * Enable the generic message digest layer.
 *
 * Module:  library/md.c
 * Caller:
 *
 * Uncomment to enable generic message digest wrappers.
 */
#define MBEDTLS_MD_C

/**
 * \def MBEDTLS_MD2_C
 *
 * Enable the MD2 hash algorithm.
 *
 * Module:  library/md2.c
 * Caller:
 *
 * Uncomment to enable support for (rare) MD2-signed X.509 certs.
 *
 * \warning   MD2 is considered a weak message digest and its use constitutes a
 *            security risk. If possible, we recommend avoiding dependencies on
 *            it, and considering stronger message digests instead.
 *
 */
//#define MBEDTLS_MD2_C

/**
 * \def MBEDTLS_MD4_C
 *
 * Enable the MD4 hash algorithm.
 *
 * Module:  library/md4.c
 * Caller:
 *
 * Uncomment to enable support for (rare) MD4-signed X.509 certs.
 *
 * \warning   MD4 is considered a weak message digest and its use constitutes a
 *            security risk. If possible, we recommend avoiding dependencies on
 *            it, and considering stronger message digests instead.
 *
 */
//#define MBEDTLS_MD4_C

/**
 * \def MBEDTLS_MD5_C
 *
 * Enable the MD5 hash algorithm.
 *
 * Module:  library/md5.c
 * Caller:  library/md.c
 *          library/pem.c
 *
 * This module is required for SSL/TLS up to version 1.1, and for TLS 1.2
 * depending on the handshake parameters. Further, it is used for checking
 * MD5-signed certificates, and for PBKDF1 when decrypting PEM-encoded
 * encrypted keys.
 *
 * \warning   MD5 is considered a weak message digest and its use constitutes a
 *            security risk. If possible, we recommend avoiding dependencies on
 *            it, and considering stronger message digests instead.
 *
 */
#define MBEDTLS_MD5_C

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
 *           MBEDTLS_PLATFORM_MEMORY (to use it within mbed TLS)
 *
 * Enable this module to enable the buffer memory allocator.
 */
//#define MBEDTLS_MEMORY_BUFFER_ALLOC_C

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
 *
 * This modules translates between OIDs and internal values.
 */
#define MBEDTLS_OID_C

/**
 * \def MBEDTLS_PADLOCK_C
 *
 * Enable VIA Padlock support on x86.
 *
 * Module:  library/padlock.c
 * Caller:  library/aes.c
 *
 * Requires: MBEDTLS_HAVE_ASM
 *
 * This modules adds support for the VIA PadLock on x86.
 */
#define MBEDTLS_PADLOCK_C

/**
 * \def MBEDTLS_PEM_PARSE_C
 *
 * Enable PEM decoding / parsing.
 *
 * Module:  library/pem.c
 * Caller:  library/dhm.c
 *          library/pkparse.c
 *
 * Requires: MBEDTLS_BASE64_C
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
 *
 * Requires: MBEDTLS_BASE64_C
 *
 * This modules adds support for encoding / writing PEM files.
 */
#define MBEDTLS_PEM_WRITE_C

/**
 * \def MBEDTLS_PK_C
 *
 * Enable the generic public (asymetric) key layer.
 *
 * Module:  library/pk.c
 *
 * Requires: MBEDTLS_RSA_C or MBEDTLS_ECP_C
 *
 * Uncomment to enable generic public key wrappers.
 */
#define MBEDTLS_PK_C

/**
 * \def MBEDTLS_PK_PARSE_C
 *
 * Enable the generic public (asymetric) key parser.
 *
 * Module:  library/pkparse.c
 *
 * Requires: MBEDTLS_PK_C
 *
 * Uncomment to enable generic public key parse functions.
 */
#define MBEDTLS_PK_PARSE_C

/**
 * \def MBEDTLS_PK_WRITE_C
 *
 * Enable the generic public (asymetric) key writer.
 *
 * Module:  library/pkwrite.c
 *
 * Requires: MBEDTLS_PK_C
 *
 * Uncomment to enable generic public key write functions.
 */
#define MBEDTLS_PK_WRITE_C

/**
 * \def MBEDTLS_PKCS5_C
 *
 * Enable PKCS#5 functions.
 *
 * Module:  library/pkcs5.c
 *
 * Requires: MBEDTLS_MD_C
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
 * Requires: MBEDTLS_ASN1_PARSE_C, MBEDTLS_CIPHER_C, MBEDTLS_MD_C
 * Can use:  MBEDTLS_ARC4_C
 *
 * This module enables PKCS#12 functions.
 */
#define MBEDTLS_PKCS12_C

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
 * as other module rely on it for a fixed snprintf implementation.
 *
 * Module:  library/platform.c
 * Caller:  Most other .c files
 *
 * This module enables abstraction of common (libc) functions.
 */
#define MBEDTLS_PLATFORM_C

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
 * \def MBEDTLS_PSA_CRYPTO_C
 *
 * Enable the Platform Security Architecture cryptography API.
 *
 * Module:  library/psa_crypto.c
 *
 * Requires: MBEDTLS_CTR_DRBG_C, MBEDTLS_ENTROPY_C
 *
 */
#define MBEDTLS_PSA_CRYPTO_C

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
 *          library/rsa_internal.c
 *
 * This module is used by the following key exchanges:
 *      RSA, DHE-RSA, ECDHE-RSA, RSA-PSK
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
 *
 * This module is required for SSL/TLS up to version 1.1, for TLS 1.2
 * depending on the handshake parameters, and for SHA1-signed certificates.
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes
 *            a security risk. If possible, we recommend avoiding dependencies
 *            on it, and considering stronger message digests instead.
 *
 */
#define MBEDTLS_SHA1_C

/**
 * \def MBEDTLS_SHA256_C
 *
 * Enable the SHA-224 and SHA-256 cryptographic hash algorithms.
 *
 * Module:  library/sha256.c
 * Caller:  library/entropy.c
 *          library/md.c
 *
 * This module adds support for SHA-224 and SHA-256.
 * This module is required for the SSL/TLS 1.2 PRF function.
 */
#define MBEDTLS_SHA256_C

/**
 * \def MBEDTLS_SHA512_C
 *
 * Enable the SHA-384 and SHA-512 cryptographic hash algorithms.
 *
 * Module:  library/sha512.c
 * Caller:  library/entropy.c
 *          library/md.c
 *
 * This module adds support for SHA-384 and SHA-512.
 */
#define MBEDTLS_SHA512_C

/**
 * \def MBEDTLS_THREADING_C
 *
 * Enable the threading abstraction layer.
 * By default mbed TLS assumes it is used in a non-threaded environment or that
 * contexts are not shared between threads. If you do intend to use contexts
 * between threads, you will need to enable this layer to prevent race
 * conditions. See also our Knowledge Base article about threading:
 * https://tls.mbed.org/kb/development/thread-safety-and-multi-threading
 *
 * Module:  library/threading.c
 *
 * This allows different threading implementations (self-implemented or
 * provided).
 *
 * You will have to enable either MBEDTLS_THREADING_ALT or
 * MBEDTLS_THREADING_PTHREAD.
 *
 * Enable this layer to allow use of mutexes within mbed TLS
 */
//#define MBEDTLS_THREADING_C

/**
 * \def MBEDTLS_TIMING_C
 *
 * Enable the semi-portable timing interface.
 *
 * \note The provided implementation only works on POSIX/Unix (including Linux,
 * BSD and OS X) and Windows. On other platforms, you can either disable that
 * module and provide your own implementations of the callbacks needed by Mbed
 * TLS's \c mbedtls_ssl_set_timer_cb() for DTLS, or leave it enabled and
 * provide your own implementation of the whole module by setting
 * \c MBEDTLS_TIMING_ALT in the current file.
 *
 * \note See also our Knowledge Base article about porting to a new
 * environment:
 * https://tls.mbed.org/kb/how-to/how-do-i-port-mbed-tls-to-a-new-environment-OS
 *
 * Module:  library/timing.c
 * Caller:  library/havege.c
 *
 * This module is used by the HAVEGE random number generator.
 */
#define MBEDTLS_TIMING_C

/**
 * \def MBEDTLS_VERSION_C
 *
 * Enable run-time version information.
 *
 * Module:  library/version.c
 *
 * This module provides run-time version information.
 */
#define MBEDTLS_VERSION_C

/**
 * \def MBEDTLS_XTEA_C
 *
 * Enable the XTEA block cipher.
 *
 * Module:  library/xtea.c
 * Caller:
 */
#define MBEDTLS_XTEA_C

/* \} name SECTION: mbed TLS modules */

/**
 * \name SECTION: Module configuration options
 *
 * This section allows for the setting of module specific sizes and
 * configuration options. The default values are already present in the
 * relevant header files and should suffice for the regular use cases.
 *
 * Our advice is to enable options and change their values here
 * only if you have a good reason and know the consequences.
 *
 * Please check the respective header file for documentation on these
 * parameters (to prevent duplicate documentation).
 * \{
 */

/* MPI / BIGNUM options */
//#define MBEDTLS_MPI_WINDOW_SIZE            6 /**< Maximum windows size used. */
//#define MBEDTLS_MPI_MAX_SIZE            1024 /**< Maximum number of bytes for usable MPIs. */

/* CTR_DRBG options */
//#define MBEDTLS_CTR_DRBG_ENTROPY_LEN               48 /**< Amount of entropy used per seed by default (48 with SHA-512, 32 with SHA-256) */
//#define MBEDTLS_CTR_DRBG_RESEED_INTERVAL        10000 /**< Interval before reseed is performed by default */
//#define MBEDTLS_CTR_DRBG_MAX_INPUT                256 /**< Maximum number of additional input bytes */
//#define MBEDTLS_CTR_DRBG_MAX_REQUEST             1024 /**< Maximum number of requested bytes per call */
//#define MBEDTLS_CTR_DRBG_MAX_SEED_INPUT           384 /**< Maximum size of (re)seed buffer */
//#define MBEDTLS_CTR_DRBG_USE_128_BIT_KEY              /**< Use 128-bit key for CTR_DRBG - may reduce security (see ctr_drbg.h) */

/* HMAC_DRBG options */
//#define MBEDTLS_HMAC_DRBG_RESEED_INTERVAL   10000 /**< Interval before reseed is performed by default */
//#define MBEDTLS_HMAC_DRBG_MAX_INPUT           256 /**< Maximum number of additional input bytes */
//#define MBEDTLS_HMAC_DRBG_MAX_REQUEST        1024 /**< Maximum number of requested bytes per call */
//#define MBEDTLS_HMAC_DRBG_MAX_SEED_INPUT      384 /**< Maximum size of (re)seed buffer */

/* ECP options */
//#define MBEDTLS_ECP_MAX_BITS             521 /**< Maximum bit size of groups */
//#define MBEDTLS_ECP_WINDOW_SIZE            6 /**< Maximum window size used */
//#define MBEDTLS_ECP_FIXED_POINT_OPTIM      1 /**< Enable fixed-point speed-up */

/* Entropy options */
//#define MBEDTLS_ENTROPY_MAX_SOURCES                20 /**< Maximum number of sources supported */
//#define MBEDTLS_ENTROPY_MAX_GATHER                128 /**< Maximum amount requested from entropy sources */
//#define MBEDTLS_ENTROPY_MIN_HARDWARE               32 /**< Default minimum number of bytes required for the hardware entropy source mbedtls_hardware_poll() before entropy is released */

/* Memory buffer allocator options */
//#define MBEDTLS_MEMORY_ALIGN_MULTIPLE      4 /**< Align on multiples of this value */

/* Platform options */
//#define MBEDTLS_PLATFORM_STD_MEM_HDR   <stdlib.h> /**< Header to include if MBEDTLS_PLATFORM_NO_STD_FUNCTIONS is defined. Don't define if no header is needed. */
//#define MBEDTLS_PLATFORM_STD_CALLOC        calloc /**< Default allocator to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_FREE            free /**< Default free to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_EXIT            exit /**< Default exit to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_TIME            time /**< Default time to use, can be undefined. MBEDTLS_HAVE_TIME must be enabled */
//#define MBEDTLS_PLATFORM_STD_FPRINTF      fprintf /**< Default fprintf to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_PRINTF        printf /**< Default printf to use, can be undefined */
/* Note: your snprintf must correctly zero-terminate the buffer! */
//#define MBEDTLS_PLATFORM_STD_SNPRINTF    snprintf /**< Default snprintf to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_EXIT_SUCCESS       0 /**< Default exit value to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_EXIT_FAILURE       1 /**< Default exit value to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_NV_SEED_READ   mbedtls_platform_std_nv_seed_read /**< Default nv_seed_read function to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_NV_SEED_WRITE  mbedtls_platform_std_nv_seed_write /**< Default nv_seed_write function to use, can be undefined */
//#define MBEDTLS_PLATFORM_STD_NV_SEED_FILE  "seedfile" /**< Seed file to read/write with default implementation */

/* To Use Function Macros MBEDTLS_PLATFORM_C must be enabled */
/* MBEDTLS_PLATFORM_XXX_MACRO and MBEDTLS_PLATFORM_XXX_ALT cannot both be defined */
//#define MBEDTLS_PLATFORM_CALLOC_MACRO        calloc /**< Default allocator macro to use, can be undefined */
//#define MBEDTLS_PLATFORM_FREE_MACRO            free /**< Default free macro to use, can be undefined */
//#define MBEDTLS_PLATFORM_EXIT_MACRO            exit /**< Default exit macro to use, can be undefined */
//#define MBEDTLS_PLATFORM_TIME_MACRO            time /**< Default time macro to use, can be undefined. MBEDTLS_HAVE_TIME must be enabled */
//#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO       time_t /**< Default time macro to use, can be undefined. MBEDTLS_HAVE_TIME must be enabled */
//#define MBEDTLS_PLATFORM_FPRINTF_MACRO      fprintf /**< Default fprintf macro to use, can be undefined */
//#define MBEDTLS_PLATFORM_PRINTF_MACRO        printf /**< Default printf macro to use, can be undefined */
/* Note: your snprintf must correctly zero-terminate the buffer! */
//#define MBEDTLS_PLATFORM_SNPRINTF_MACRO    snprintf /**< Default snprintf macro to use, can be undefined */
//#define MBEDTLS_PLATFORM_VSNPRINTF_MACRO    vsnprintf /**< Default vsnprintf macro to use, can be undefined */
//#define MBEDTLS_PLATFORM_NV_SEED_READ_MACRO   mbedtls_platform_std_nv_seed_read /**< Default nv_seed_read function to use, can be undefined */
//#define MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO  mbedtls_platform_std_nv_seed_write /**< Default nv_seed_write function to use, can be undefined */

/**
 * Uncomment the macro to let mbed TLS use your alternate implementation of
 * mbedtls_platform_zeroize(). This replaces the default implementation in
 * platform_util.c.
 *
 * mbedtls_platform_zeroize() is a widely used function across the library to
 * zero a block of memory. The implementation is expected to be secure in the
 * sense that it has been written to prevent the compiler from removing calls
 * to mbedtls_platform_zeroize() as part of redundant code elimination
 * optimizations. However, it is difficult to guarantee that calls to
 * mbedtls_platform_zeroize() will not be optimized by the compiler as older
 * versions of the C language standards do not provide a secure implementation
 * of memset(). Therefore, MBEDTLS_PLATFORM_ZEROIZE_ALT enables users to
 * configure their own implementation of mbedtls_platform_zeroize(), for
 * example by using directives specific to their compiler, features from newer
 * C standards (e.g using memset_s() in C11) or calling a secure memset() from
 * their system (e.g explicit_bzero() in BSD).
 */
//#define MBEDTLS_PLATFORM_ZEROIZE_ALT

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

/* \} name SECTION: Customisation configuration options */

/* Target and application specific configurations
 *
 * Allow user to override any previous default.
 *
 */
#if defined(MBEDTLS_USER_CONFIG_FILE)
#include MBEDTLS_USER_CONFIG_FILE
#endif

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
