/*
 *  Threading abstraction layer
 *
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

/*
 * Ensure gmtime_r is available even with -std=c99; must be defined before
 * mbedtls_config.h, which pulls in glibc's features.h. Harmless on other platforms.
 */
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

#include "common.h"

#if defined(MBEDTLS_THREADING_C)

#include "mbedtls/threading.h"

#if defined(MBEDTLS_HAVE_TIME_DATE) && !defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)

#if !defined(_WIN32) && (defined(unix) || \
    defined(__unix) || defined(__unix__) || (defined(__APPLE__) && \
    defined(__MACH__)))
#include <unistd.h>
#endif /* !_WIN32 && (unix || __unix || __unix__ ||
        * (__APPLE__ && __MACH__)) */

#if !( ( defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L ) ||     \
       ( defined(_POSIX_THREAD_SAFE_FUNCTIONS ) &&                     \
         _POSIX_THREAD_SAFE_FUNCTIONS >= 200112L ) )
/*
 * This is a convenience shorthand macro to avoid checking the long
 * preprocessor conditions above. Ideally, we could expose this macro in
 * platform_util.h and simply use it in platform_util.c, threading.c and
 * threading.h. However, this macro is not part of the Mbed TLS public API, so
 * we keep it private by only defining it in this file
 */

#if ! ( defined(_WIN32) && !defined(EFIX64) && !defined(EFI32) )
#define THREADING_USE_GMTIME
#endif /* ! ( defined(_WIN32) && !defined(EFIX64) && !defined(EFI32) ) */

#endif /* !( ( defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L ) ||     \
             ( defined(_POSIX_THREAD_SAFE_FUNCTIONS ) &&                     \
                _POSIX_THREAD_SAFE_FUNCTIONS >= 200112L ) ) */

#endif /* MBEDTLS_HAVE_TIME_DATE && !MBEDTLS_PLATFORM_GMTIME_R_ALT */

#if defined(MBEDTLS_THREADING_PTHREAD)
static void threading_mutex_init_pthread( mbedtls_threading_mutex_t *mutex )
{
    if( mutex == NULL )
        return;

    /* A nonzero value of is_valid indicates a successfully initialized
     * mutex. This is a workaround for not being able to return an error
     * code for this function. The lock/unlock functions return an error
     * if is_valid is nonzero. The Mbed TLS unit test code uses this field
     * to distinguish more states of the mutex; see
     * tests/src/threading_helpers for details. */
    mutex->is_valid = pthread_mutex_init( &mutex->mutex, NULL ) == 0;
}

static void threading_mutex_free_pthread( mbedtls_threading_mutex_t *mutex )
{
    if( mutex == NULL || !mutex->is_valid )
        return;

    (void) pthread_mutex_destroy( &mutex->mutex );
    mutex->is_valid = 0;
}

static int threading_mutex_lock_pthread( mbedtls_threading_mutex_t *mutex )
{
    if( mutex == NULL || ! mutex->is_valid )
        return( MBEDTLS_ERR_THREADING_BAD_INPUT_DATA );

    if( pthread_mutex_lock( &mutex->mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );

    return( 0 );
}

static int threading_mutex_unlock_pthread( mbedtls_threading_mutex_t *mutex )
{
    if( mutex == NULL || ! mutex->is_valid )
        return( MBEDTLS_ERR_THREADING_BAD_INPUT_DATA );

    if( pthread_mutex_unlock( &mutex->mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );

    return( 0 );
}

void (*mbedtls_mutex_init)( mbedtls_threading_mutex_t * ) = threading_mutex_init_pthread;
void (*mbedtls_mutex_free)( mbedtls_threading_mutex_t * ) = threading_mutex_free_pthread;
int (*mbedtls_mutex_lock)( mbedtls_threading_mutex_t * ) = threading_mutex_lock_pthread;
int (*mbedtls_mutex_unlock)( mbedtls_threading_mutex_t * ) = threading_mutex_unlock_pthread;

/*
 * With phtreads we can statically initialize mutexes
 */
#define MUTEX_INIT  = { PTHREAD_MUTEX_INITIALIZER, 1 }

#endif /* MBEDTLS_THREADING_PTHREAD */

void mbedtls_rwlock_init( mbedtls_threading_rwlock_t *lock )
{
    if( lock == NULL || lock->is_valid )
        return;

    mbedtls_mutex_init( &lock->readers_mutex );
    mbedtls_mutex_init( &lock->writer_mutex );
    lock->num_readers = 0;
    if( lock->readers_mutex.is_valid && lock->writer_mutex.is_valid )
        lock->is_valid = 1;
}

void mbedtls_rwlock_free( mbedtls_threading_rwlock_t *lock )
{
    if( lock == NULL || ! lock->is_valid )
        return;

    mbedtls_mutex_free( &lock->readers_mutex );
    mbedtls_mutex_free( &lock->writer_mutex );
    lock->is_valid = 0;
}

int mbedtls_rwlock_lock_reader( mbedtls_threading_rwlock_t *lock )
{
    int status = MBEDTLS_ERR_THREADING_MUTEX_ERROR;

    if( lock == NULL )
        return (MBEDTLS_ERR_THREADING_BAD_INPUT_DATA);
    if( !lock->is_valid )
        return (MBEDTLS_ERR_THREADING_MUTEX_ERROR);

    if( (status = mbedtls_mutex_lock( &lock->readers_mutex ) != 0 ))
        return status;

    lock->num_readers++;
    if( lock->num_readers == 1 )
    {
        if( (status = mbedtls_mutex_lock( &lock->writer_mutex ) != 0 ))
        {
            lock->num_readers--;
            mbedtls_mutex_unlock( &lock->readers_mutex );
            return status;
        }
    }
    status = mbedtls_mutex_unlock( &lock->readers_mutex );

    return status;
}

int mbedtls_rwlock_unlock_reader( mbedtls_threading_rwlock_t *lock )
{
    int status = MBEDTLS_ERR_THREADING_MUTEX_ERROR;

    if( lock == NULL )
        return (MBEDTLS_ERR_THREADING_BAD_INPUT_DATA);
    if( !lock->is_valid )
        return (MBEDTLS_ERR_THREADING_MUTEX_ERROR);

    if( (status = mbedtls_mutex_lock( &lock->readers_mutex ) != 0 ))
        return status;

    lock->num_readers--;
    if( lock->num_readers == 0 )
    {
        if( (status = mbedtls_mutex_unlock( &lock->writer_mutex ) != 0 ))
        {
            lock->num_readers++;
            mbedtls_mutex_unlock( &lock->readers_mutex );
            return status;
        }
    }
    status = mbedtls_mutex_unlock( &lock->readers_mutex );

    return status;
}

int mbedtls_rwlock_lock_writer( mbedtls_threading_rwlock_t *lock )
{
    if( lock == NULL )
        return (MBEDTLS_ERR_THREADING_BAD_INPUT_DATA);
    if( !lock->is_valid )
        return (MBEDTLS_ERR_THREADING_MUTEX_ERROR);

    return( mbedtls_mutex_lock( &lock->writer_mutex ) );
}

int mbedtls_rwlock_unlock_writer( mbedtls_threading_rwlock_t *lock )
{
    if( lock == NULL )
        return (MBEDTLS_ERR_THREADING_BAD_INPUT_DATA);
    if( !lock->is_valid )
        return (MBEDTLS_ERR_THREADING_MUTEX_ERROR);

    return( mbedtls_mutex_unlock( &lock->writer_mutex ) );
}

#if defined(MBEDTLS_THREADING_ALT)
static int threading_mutex_fail( mbedtls_threading_mutex_t *mutex )
{
    ((void) mutex );
    return( MBEDTLS_ERR_THREADING_BAD_INPUT_DATA );
}
static void threading_mutex_dummy( mbedtls_threading_mutex_t *mutex )
{
    ((void) mutex );
    return;
}

void (*mbedtls_mutex_init)( mbedtls_threading_mutex_t * ) = threading_mutex_dummy;
void (*mbedtls_mutex_free)( mbedtls_threading_mutex_t * ) = threading_mutex_dummy;
int (*mbedtls_mutex_lock)( mbedtls_threading_mutex_t * ) = threading_mutex_fail;
int (*mbedtls_mutex_unlock)( mbedtls_threading_mutex_t * ) = threading_mutex_fail;

/*
 * Set functions pointers and initialize global mutexes
 */
void mbedtls_threading_set_alt( void (*mutex_init)( mbedtls_threading_mutex_t * ),
                       void (*mutex_free)( mbedtls_threading_mutex_t * ),
                       int (*mutex_lock)( mbedtls_threading_mutex_t * ),
                       int (*mutex_unlock)( mbedtls_threading_mutex_t * ) )
{
    mbedtls_mutex_init = mutex_init;
    mbedtls_mutex_free = mutex_free;
    mbedtls_mutex_lock = mutex_lock;
    mbedtls_mutex_unlock = mutex_unlock;

#if defined(MBEDTLS_FS_IO)
    mbedtls_mutex_init( &mbedtls_threading_readdir_mutex );
#endif
#if defined(THREADING_USE_GMTIME)
    mbedtls_mutex_init( &mbedtls_threading_gmtime_mutex );
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
    mbedtls_rwlock_init( &mbedtls_psa_slots_lock );
#endif
}

/*
 * Free global mutexes
 */
void mbedtls_threading_free_alt( void )
{
#if defined(MBEDTLS_FS_IO)
    mbedtls_mutex_free( &mbedtls_threading_readdir_mutex );
#endif
#if defined(THREADING_USE_GMTIME)
    mbedtls_mutex_free( &mbedtls_threading_gmtime_mutex );
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
    mbedtls_rwlock_free( &mbedtls_psa_slots_lock );
#endif
}
#endif /* MBEDTLS_THREADING_ALT */

/*
 * Define global mutexes
 */
#ifndef MUTEX_INIT
#define MUTEX_INIT
#endif
#if defined(MBEDTLS_FS_IO)
mbedtls_threading_mutex_t mbedtls_threading_readdir_mutex MUTEX_INIT;
#endif
#if defined(THREADING_USE_GMTIME)
mbedtls_threading_mutex_t mbedtls_threading_gmtime_mutex MUTEX_INIT;
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
mbedtls_threading_rwlock_t mbedtls_psa_slots_lock;
#endif
#endif /* MBEDTLS_THREADING_C */
