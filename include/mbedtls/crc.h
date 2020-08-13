/*
 *  CRC-16/ARC implementation, generated using pycrc v0.9.2, https://pycrc.org.
 *
 *  Used options: --model=crc-16 --algorithm=tbl --generate=h --std=C89 --table-idx-width 4
 *
 *  Copyright (C) 2006-2020, ARM Limited, All Rights Reserved
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

#ifndef MBEDTLS_CRC_H
#define MBEDTLS_CRC_H

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Update the crc value with new data.
 *
 * \param[in] crc      The current crc value.
 * \param[in] data     Pointer to a buffer of \a data_len bytes.
 * \param[in] data_len Number of bytes in the \a data buffer.
 * \return             The updated crc value.
 */
uint16_t mbedtls_crc_update( uint16_t crc, const void *data, size_t data_len );

#ifdef __cplusplus
}
#endif
#endif      /* MBEDTLS_CRC_H */
