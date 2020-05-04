/**
 * \file psa/crypto_driver.h
 * \brief PSA cryptoprocessor driver interface
 *
 * This header declares types and function signatures for cryptoprocessor
 * drivers.
 *
 * This file is part of the PSA Crypto Driver Model, containing functions for
 * driver developers to implement to enable hardware to be called in a
 * standardized way by a PSA Cryptographic API implementation. The functions
 * comprising the driver model, which driver authors implement, are not
 * intended to be called by application developers.
 */

/*
 *  Copyright (C) 2020, ARM Limited, All Rights Reserved
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
 */
#ifndef PSA_CRYPTO_DRIVER_H
#define PSA_CRYPTO_DRIVER_H

#include <stddef.h>
#include <stdint.h>

/* Include type definitions (psa_status_t, psa_algorithm_t,
 * psa_key_type_t, etc.) and macros to build and analyze values
 * of these types. */
#include "crypto_types.h"
#include "crypto_values.h"

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_DRIVER_H */
