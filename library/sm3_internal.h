/**
 * \file sm3_internal.h
 *
 * \brief Internal SM3 message digest API
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

/**
 * \brief          This function processes a single data block within
 *                 the ongoing SM3 computation. This function is for
 *                 internal use only.
 *
 * \param ctx      The SM3 context. This must be initialized.
 * \param data     The buffer holding one block of data. This must
 *                 be a readable buffer of length \c 64 Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */

#ifndef MBEDTLS_SM3_INTERNAL_H
#define MBEDTLS_SM3_INTERNAL_H

#include "mbedtls/sm3.h"

int mbedtls_internal_sm3_process( mbedtls_sm3_context *ctx,
                                  const unsigned char data[64] );

#endif /* sm3_internal.h */

