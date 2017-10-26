/*
 *  mbed TLS utility functions
 *
 *  Copyright (C) 2017, ARM Limited, All Rights Reserved
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

#include "mbedtls/utils.h"

#include <stddef.h>
#include <string.h>

#if !defined(MBEDTLS_UTILS_ZEROIZE_ALT)
/*
 * This implementation should never be optimized out by the compiler
 *
 * This implementation for mbedtls_zeroize() uses a volatile function pointer.
 * We always know that it points to memset(), but because it is volatile the
 * compiler expects it to change at any time and will not optimize out the
 * call that could potentially perform other operations on the input buffer
 * instead of just setting it to 0. Nevertheless, optimizations of the
 * following form are still possible:
 *
 * if( memset_func != memset )
 *     memset_func( buf, 0, len );
 *
 * Note that it is extremely difficult to guarantee that mbedtls_zeroize()
 * will not be optimized out by aggressive compilers in a portable way. For
 * this reason, mbed TLS also provides the configuration option
 * MBEDTLS_UTILS_ZEROIZE_ALT, which allows users to configure
 * mbedtls_zeroize() to use a suitable implementation for their platform and
 * needs.
 */
static void * (* const volatile memset_func)( void *, int, size_t ) = memset;

void mbedtls_zeroize( void *buf, size_t len )
{
    memset_func( buf, 0, len );
}
#endif /* MBEDTLS_UTILS_ZEROIZE_ALT */
