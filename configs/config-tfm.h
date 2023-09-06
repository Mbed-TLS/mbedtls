/**
 * \file config-tfm.h
 *
 * \brief TF-M configuration with tweaks for a successful build and test.
 */
/*
 *  Copyright The Mbed TLS Contributors
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

/* TF-M Configuration Options */
#include "../configs/ext/tfm_mbedcrypto_config_profile_medium.h"

/* TF-M PSA Crypto Configuration */
#define MBEDTLS_PSA_CRYPTO_CONFIG_FILE "../configs/ext/crypto_config_profile_medium.h"
