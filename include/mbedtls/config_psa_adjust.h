/**
 * \file mbedtls/config_psa_adjust.h
 * \brief Adjust the PSA crypto configuration (PSA_WANT_xxx symbols)
 *        to automatically enable certain features.
 *
 * Do not include this header directly! It is automatically included
 * by public headers as needed.
 *
 * This file automatically enables certain features when it would be
 * too complicated and basically useless not to (e.g. when there is
 * no practical use for enabling A without B, or when A+B requires almost
 * no extra code compared with A lone).
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

#ifndef MBEDTLS_CONFIG_PSA_ADJUST_H
#define MBEDTLS_CONFIG_PSA_ADJUST_H

#endif /* MBEDTLS_CONFIG_PSA_ADJUST_H */
