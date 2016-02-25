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
 * Here we separate out the detection of the
 * optional Crypto extensions.
 *
 * To limit complexity we will only support
 * ARMv8, A profile, AArch64 code on Linux
 *
 * If the platform is suitable, then we define
 * MBEDTLS_HAVE_ARM_CRYPTO which should then be
 * used whenever a platform test is required.
 *
 */



#if defined(__GNUC__) && \
	defined(linux) && \
	__ARM_ARCH >= 8 && \
	__ARM_ARCH_PROFILE == 'A' && \
    defined(__ARM_64BIT_STATE)  &&  \
	defined(__ARM_FEATURE_CRYPTO) && \
    ! defined(MBEDTLS_HAVE_ARM_CRYPTO)

#define MBEDTLS_HAVE_ARM_CRYPTO

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/auxv.h>
#include <asm/hwcap.h>

#define MBEDTLS_ARM_CRYTO_CRC32	HWCAP_CRC32
#define MBEDTLS_ARM_CRYTO_SHA2	HWCAP_SHA2
#define MBEDTLS_ARM_CRYTO_SHA1	HWCAP_SHA1
#define MBEDTLS_ARM_CRYTO_AES	HWCAP_AES
#define MBEDTLS_ARM_CRYTO_PMULL HWCAP_PMULL

#define mbedtls_arm_has_support( what ) ((getauxval(AT_HWCAP) & what) != 0)

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_HAVE_ARM_CRYPTO */

#endif /* MBEDTLS_CONFIG_ARM_TEST_H */
