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

/** Mutex usage verification framework.
 *
 * The mutex usage verification code below aims to detect bad usage of
 * Mbed TLS's mutex abstraction layer at runtime. Note that this is solely
 * about the use of the mutex itself, not about checking whether the mutex
 * correctly protects whatever it is supposed to protect.
 *
 * The normal usage of a mutex is:
 * ```
 * digraph mutex_states {
 *   "UNINITIALIZED"; // the initial state
 *   "IDLE";
 *   "FREED";
 *   "LOCKED";
 *   "UNINITIALIZED" -> "IDLE" [label="init"];
 *   "FREED" -> "IDLE" [label="init"];
 *   "IDLE" -> "LOCKED" [label="lock"];
 *   "LOCKED" -> "IDLE" [label="unlock"];
 *   "IDLE" -> "FREED" [label="free"];
 * }
 * ```
 *
 * All bad transitions that can be unambiguously detected are reported.
 * An attempt to use an uninitialized mutex cannot be detected in general
 * since the memory content may happen to denote a valid state. For the same
 * reason, a double init cannot be detected.
 * All-bits-zero is the state of a freed mutex, which is distinct from an
 * initialized mutex, so attempting to use zero-initialized memory as a mutex
 * without calling the init function is detected.
 *
 * If an error is detected, this framework will report what happened and the
 * test case will be marked as failed. Unfortunately, the error report cannot
 * indicate the exact location of the problematic call. To locate the error,
 * use a debugger and set a breakpoint on mbedtls_test_mutex_usage_error().
 */
enum value_of_mutex_is_valid
{
    MUTEX_FREED = 0, //!< Set by threading_mutex_free_pthread
    MUTEX_IDLE = 1, //!< Set by threading_mutex_init_pthread and by our unlock
    MUTEX_LOCKED = 2, //!< Set by our lock
};

typedef struct
{
    void (*init)( mbedtls_threading_mutex_t * );
    void (*free)( mbedtls_threading_mutex_t * );
    int (*lock)( mbedtls_threading_mutex_t * );
    int (*unlock)( mbedtls_threading_mutex_t * );
} mutex_functions_t;
static mutex_functions_t mutex_functions;

static void mbedtls_test_mutex_usage_error( mbedtls_threading_mutex_t *mutex,
                                            const char *msg )
{
    (void) mutex;
    if( mbedtls_test_info.mutex_usage_error == NULL )
        mbedtls_test_info.mutex_usage_error = msg;
    mbedtls_fprintf( stdout, "[mutex: %s] ", msg );
    /* Don't mark the test as failed yet. This way, if the test fails later
     * for a functional reason, the test framework will report the message
     * and location for this functional reason. If the test passes,
     * mbedtls_test_mutex_usage_check() will mark it as failed. */
}

static void mbedtls_test_wrap_mutex_init( mbedtls_threading_mutex_t *mutex )
{
    mutex_functions.init( mutex );
}

static void mbedtls_test_wrap_mutex_free( mbedtls_threading_mutex_t *mutex )
{
    switch( mutex->is_valid )
    {
        case MUTEX_FREED:
            mbedtls_test_mutex_usage_error( mutex, "free without init or double free" );
            break;
        case MUTEX_IDLE:
            /* Do nothing. The underlying free function will reset is_valid
             * to 0. */
            break;
        case MUTEX_LOCKED:
            mbedtls_test_mutex_usage_error( mutex, "free without unlock" );
            break;
        default:
            mbedtls_test_mutex_usage_error( mutex, "corrupted state" );
            break;
    }
    mutex_functions.free( mutex );
}

static int mbedtls_test_wrap_mutex_lock( mbedtls_threading_mutex_t *mutex )
{
    int ret = mutex_functions.lock( mutex );
    switch( mutex->is_valid )
    {
        case MUTEX_FREED:
            mbedtls_test_mutex_usage_error( mutex, "lock without init" );
            break;
        case MUTEX_IDLE:
            if( ret == 0 )
                mutex->is_valid = 2;
            break;
        case MUTEX_LOCKED:
            mbedtls_test_mutex_usage_error( mutex, "double lock" );
            break;
        default:
            mbedtls_test_mutex_usage_error( mutex, "corrupted state" );
            break;
    }
    return( ret );
}

static int mbedtls_test_wrap_mutex_unlock( mbedtls_threading_mutex_t *mutex )
{
    int ret = mutex_functions.unlock( mutex );
    switch( mutex->is_valid )
    {
        case MUTEX_FREED:
            mbedtls_test_mutex_usage_error( mutex, "unlock without init" );
            break;
        case MUTEX_IDLE:
            mbedtls_test_mutex_usage_error( mutex, "unlock without lock" );
            break;
        case MUTEX_LOCKED:
            if( ret == 0 )
                mutex->is_valid = MUTEX_IDLE;
            break;
        default:
            mbedtls_test_mutex_usage_error( mutex, "corrupted state" );
            break;
    }
    return( ret );
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

void mbedtls_test_mutex_usage_check( void )
{
    if( mbedtls_test_info.mutex_usage_error != NULL &&
        mbedtls_test_info.result != MBEDTLS_TEST_RESULT_FAILED )
    {
        /* Functionally, the test passed. But there was a mutex usage error,
         * so mark the test as failed after all. */
        mbedtls_test_fail( "Mutex usage error", __LINE__, __FILE__ );
    }
    mbedtls_test_info.mutex_usage_error = NULL;
}

#endif /* MBEDTLS_TEST_MUTEX_USAGE */
