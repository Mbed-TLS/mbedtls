/*
 *  PSA crypto support for secure element drivers
 */
/*  Copyright (C) 2019, ARM Limited, All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#ifndef PSA_CRYPTO_SE_H
#define PSA_CRYPTO_SE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"

/** The maximum number of registered secure element driver lifetimes. */
#define PSA_MAX_SE_DRIVERS 4

/** Unregister all secure element drivers.
 *
 * \warning Do not call this function while the library is in the initialized
 *          state. This function is only intended to be called at the end
 *          of mbedtls_psa_crypto_free().
 */
void psa_unregister_all_se_drivers( void );

#endif /* PSA_CRYPTO_SE_H */
