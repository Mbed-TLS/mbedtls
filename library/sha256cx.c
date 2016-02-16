/*
 *  SHA256-CX support functions
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SHA256CX_C)

#include "mbedtls/sha256cx.h"

#include <string.h>

#ifndef asm
#define asm __asm
#endif

#if defined(MBEDTLS_HAVE_AARCH64)

/*
 * SHA256-CX support detection routine
 */
int mbedtls_sha256cx_has_support( unsigned int what )
{
    static int done = 0;
    static unsigned int c = 0;

    if( ! done )
    {
        /** \todo add feature test here */
        done = 1;
    }

    return( ( c & what ) != 0 );
}

#endif /* MBEDTLS_HAVE_AARCH64 */

#endif /* MBEDTLS_SHA256CX_C */
