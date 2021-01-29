/** Mutex usage verification framework. */

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

#include <test/helpers.h>
#include <test/macros.h>

#if defined(MBEDTLS_TEST_MUTEX_USAGE)

#include "mbedtls/threading.h"

typedef struct
{
    void (*init)( mbedtls_threading_mutex_t * );
    void (*free)( mbedtls_threading_mutex_t * );
    int (*lock)( mbedtls_threading_mutex_t * );
    int (*unlock)( mbedtls_threading_mutex_t * );
} mutex_functions_t;
static mutex_functions_t mutex_functions;

static void mbedtls_test_wrap_mutex_init( mbedtls_threading_mutex_t *mutex )
{
    mutex_functions.init( mutex );
}

static void mbedtls_test_wrap_mutex_free( mbedtls_threading_mutex_t *mutex )
{
    mutex_functions.free( mutex );
}

static int mbedtls_test_wrap_mutex_lock( mbedtls_threading_mutex_t *mutex )
{
    int ret = mutex_functions.lock( mutex );
    return( ret );
}

static int mbedtls_test_wrap_mutex_unlock( mbedtls_threading_mutex_t *mutex )
{
    return( mutex_functions.unlock( mutex ) );
}

void mbedtls_test_mutex_usage_init( void )
{
    mutex_functions.init = mbedtls_mutex_init;
    mutex_functions.free = mbedtls_mutex_free;
    mutex_functions.lock = mbedtls_mutex_lock;
    mutex_functions.unlock = mbedtls_mutex_unlock;
    mbedtls_mutex_init = &mbedtls_test_wrap_mutex_init;
    mbedtls_mutex_free = &mbedtls_test_wrap_mutex_free;
    mbedtls_mutex_lock = &mbedtls_test_wrap_mutex_lock;
    mbedtls_mutex_unlock = &mbedtls_test_wrap_mutex_unlock;
}

#endif /* MBEDTLS_TEST_MUTEX_USAGE */
