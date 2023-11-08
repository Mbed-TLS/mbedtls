/**
 * \file mbedtls/config_adjust_x509.h
 * \brief Adjust X.509 configuration
 *
 * Automatically enable certain dependencies. Generally, MBEDLTS_xxx
 * configurations need to be explicitly enabled by the user: enabling
 * MBEDTLS_xxx_A but not MBEDTLS_xxx_B when A requires B results in a
 * compilation error. However, we do automatically enable certain options
 * in some circumstances. One case is if MBEDTLS_xxx_B is an internal option
 * used to identify parts of a module that are used by other module, and we
 * don't want to make the symbol MBEDTLS_xxx_B part of the public API.
 * Another case is if A didn't depend on B in earlier versions, and we
 * want to use B in A but we need to preserve backward compatibility with
 * configurations that explicitly activate MBEDTLS_xxx_A but not
 * MBEDTLS_xxx_B.
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

#ifndef MBEDTLS_CONFIG_ADJUST_X509_H
#define MBEDTLS_CONFIG_ADJUST_X509_H

#endif /* MBEDTLS_CONFIG_ADJUST_X509_H */
