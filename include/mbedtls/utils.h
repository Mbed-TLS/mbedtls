/**
 * \file utils.h
 *
 * \brief Mbed TLS utility functions
 *
 *  Copyright (C) 2018, Arm Limited, All Rights Reserved
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
#ifndef MBEDTLS_UTILS_H
#define MBEDTLS_UTILS_H

#include <stddef.h>

/**
 * \brief       Securely zeroize a buffer
 *
 * \param buf   Buffer to be zeroized
 * \param len   Length of the buffer in bytes
 *
 * \note        This implementation should never be optimized out by the
 *              compiler
 *
 * \note        It is extremely difficult to guarantee that calls to
 *              mbedtls_zeroize() are not removed by aggressive compiler
 *              optimizations in a portable way. For this reason, Mbed TLS
 *              provides the configuration option MBEDTLS_UTILS_ZEROIZE_ALT,
 *              which allows users to configure mbedtls_zeroize() to use a
 *              suitable implementation for their platform and needs
 */
void mbedtls_zeroize( void *buf, size_t len );

#endif /* MBEDTLS_UTILS_H */
