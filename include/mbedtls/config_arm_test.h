/**
 * \file config_arm_test.h
 *
 * \brief Compile and runtime checks for ARM features to accelerate crypto
 *
 *  Copyright (C) 2016, CriticalBlue Limited, All Rights Reserved
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

/*
 * Include this file at the start of the header for any ARM specific module
 */

#ifndef MBEDTLS_CONFIG_ARM_TEST_H
#define MBEDTLS_CONFIG_ARM_TEST_H


/*
 * Set compile time flags for capabilities
 * Here we separate out the detection of NEON
 * and the optional Crypto extensions.
 *
 * To limit complexity we will only support
 * ARMv8, A profile, AArch64 code.
 *
 */

#if defined(__GNUC__) && __ARM_ARCH >= 8 && \
    defined(__ARM_64BIT_STATE)  &&  __ARM_ARCH_PROFILE == 'A' && \
    ! defined(MBEDTLS_HAVE_ARM_NEON)
/* We always have NEON in this case */
#define MBEDTLS_HAVE_ARM_NEON
#endif


/* Check for the optional Crypto extensions now */
#if defined(MBEDTLS_HAVE_ARM_NEON) && defined(__ARM_FEATURE_CRYPTO) && ! defined(MBEDTLS_HAVE_ARM_CRYPTO)
#define MBEDTLS_HAVE_ARM_CRYPTO
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(linux)
#include <sys/auxv.h>
#include <asm/hwcap.h>

#define MBEDTLS_ARM_CRYTO_CRC32	HWCAP_CRC32
#define MBEDTLS_ARM_CRYTO_SHA2	HWCAP_SHA2
#define MBEDTLS_ARM_CRYTO_SHA1	HWCAP_SHA1
#define MBEDTLS_ARM_CRYTO_AES	HWCAP_AES
#define MBEDTLS_ARM_CRYTO_PMULL HWCAP_PMULL

#define mbedtls_arm_has_support( what ) ((getauxval(AT_HWCAP) & what) != 0)

#else /* Not Linux so don't have a solution for accessing EL1 registers just now */

#define MBEDTLS_ARM_CRYTO_CRC32	0
#define MBEDTLS_ARM_CRYTO_SHA2	0
#define MBEDTLS_ARM_CRYTO_SHA1	0
#define MBEDTLS_ARM_CRYTO_AES	0
#define MBEDTLS_ARM_CRYTO_PMULL 0

#define mbedtls_arm_has_support( what ) (0)

#endif /* defined(linux) */



#ifdef __cplusplus
}
#endif


/* Check that we are delivering what the config file is expecting */

#if defined(MBEDTLS_ARM_NEON_C) && ( !defined(MBEDTLS_HAVE_ARM_NEON) )
#error "MBEDTLS_ARM_NEON_C defined in config.h but support not available on platform. Try adding ARMCRYPTO=1 to make command line."
#endif

#if defined(MBEDTLS_ARM_CRYTO_C) && ( !defined(MBEDTLS_HAVE_ARM_CRYPTO) )
#error "MBEDTLS_ARM_CRYTO_C defined in config.h but support not available on platform. Try adding ARMCRYPTO=1 to make command line."

#endif

#endif /* MBEDTLS_CONFIG_ARM_TEST_H */
