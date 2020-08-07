/*
 *  CRC-16/ARC implementation, generated using pycrc v0.9.2, https://pycrc.org,
 *  with further FI countermeasures added manually.
 *
 *  Used options: --model=crc-16 --algorithm=tbl --generate=c --std=C89 --table-idx-width 4
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CRC_C)

#include "mbedtls/crc.h"

static const uint32_t crc_table[16] = {
    0x0000, 0xcc01, 0xd801, 0x1400, 0xf001, 0x3c00, 0x2800, 0xe401,
    0xa001, 0x6c00, 0x7800, 0xb401, 0x5000, 0x9c01, 0x8801, 0x4400
};

uint16_t mbedtls_crc_update( uint16_t crc, const void *data, size_t data_len )
{
    const unsigned char *d = (const unsigned char *)data;
    unsigned int tbl_idx;

    while ( data_len -- ) {
        tbl_idx = crc ^ *d;
        crc = crc_table[tbl_idx & 0x0f] ^ ( crc >> 4 );
        tbl_idx = crc ^ ( *d >> 4 );
        crc = crc_table[tbl_idx & 0x0f] ^ ( crc >> 4 );
        d ++;
    }
    return crc;
}

#endif /* MBEDTLS_CRC_C */
