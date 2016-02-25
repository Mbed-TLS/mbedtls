/**
 * \file aescryptoext.h
 *
 * \brief AES Crypto Extension for hardware AES acceleration on some ARMv8-A processors.
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
#ifndef MBEDTLS_AESCRYPTOEXT_H
#define MBEDTLS_AES_ARMCRYPTO_H

#include "aes.h"
#include "config_arm_test.h"

/*
 * Enable this module if requested in the config.h
 * We only want to incude this code if both AES and ARM Crypto
 * are configured
 */
#if defined(MBEDTLS_ARM_CRYTO_C) && defined(MBEDTLS_AES_C)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          AES ARM Crypto AES-ECB block en(de)cryption
 *
 * \param ctx      AES context
 * \param mode     MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 on success (cannot fail)
 */
int mbedtls_aes_armcrypto_crypt_ecb( mbedtls_aes_context *ctx,
                     int mode,
                     const unsigned char input[16],
                     unsigned char output[16] );

/**
 * \brief          GCM multiplication: c = a * b in GF(2^128)
 *
 * \param c        Result
 * \param a        First operand
 * \param b        Second operand
 *
 * \note           Both operands and result are bit strings interpreted as
 *                 elements of GF(2^128) as per the GCM spec.
 */
void mbedtls_aes_armcrypto_gcm_mult( unsigned char c[16],
                     const unsigned char a[16],
                     const unsigned char b[16] );


#ifdef __cplusplus
}
#endif

#endif /* defined(MBEDTLS_ARM_CRYTO_C)*/

#endif /* MBEDTLS_AES_ARMCRYPTO_H */
