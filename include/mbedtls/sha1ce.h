/**
 * \file sha1ce.h
 *
 * \brief SHA1-CE for hardware SHA1 acceleration on some ARM processors
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
#ifndef MBEDTLS_SHA1CE_H
#define MBEDTLS_SHA1CE_H

#include "sha1.h"
#include "config_arm_test.h"
/*
 * Enable this module if requested in the config.h
 * We only want to incude this code if both SHA1 and ARM Crypto
 * are configured
 */
#if defined(MBEDTLS_ARM_CRYTO_C) && defined(MBEDTLS_SHA1_C) && defined(MBEDTLS_HAVE_ARM_CRYPTO)


#ifdef __cplusplus
extern "C" {
#endif


/* Internal use */
void mbedtls_sha1ce_process( mbedtls_sha1_context *ctx, const unsigned char data[64] );

#ifdef __cplusplus
}
#endif

#endif /*  defined(MBEDTLS_ARM_CRYTO_C) && defined(MBEDTLS_SHA1_C) */

#endif /* MBEDTLS_SHA1CE_H */
