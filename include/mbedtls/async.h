/**
 * \file async.h
 *
 * \brief Asynchronous operation abstraction layer
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

#ifndef MBEDTLS_ASYNC_H
#define MBEDTLS_ASYNC_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>



/** \name Error codes */
/**@{*/

#define MBEDTLS_ERR_ASYNC_BAD_STATE           -0x0011  /**< Action attempted on an asynchronous operation in the wrong state */
#define MBEDTLS_ERR_ASYNC_IN_PROGRESS         -0x0013  /**< Asynchronous operation unfinished, call mbedtls_async_resume */
#define MBEDTLS_ERR_ASYNC_CANCELLED           -0x0015  /**< Asynchronous operation cancelled by the caller */
#define MBEDTLS_ERR_ASYNC_ALLOC_FAILED        -0x0017  /**< Out of memory */

/**@}*/

#ifdef __cplusplus
extern "C" {
#endif



/** \name Common types */
/**@{*/

/** Asynchronous operation types */
typedef enum
{
    MBEDTLS_ASYNC_OP_NULL,          /**< No operation */
    MBEDTLS_ASYNC_OP_PK_SIGN,       /**< mbedtls_pk_async_sign() */
    MBEDTLS_ASYNC_OP_PK_VERIFY,     /**< mbedtls_pk_async_verify() */
    MBEDTLS_ASYNC_OP_PK_ENCRYPT,    /**< mbedtls_pk_async_encrypt() */
    MBEDTLS_ASYNC_OP_PK_DECRYPT,    /**< mbedtls_pk_async_decrypt() */
} mbedtls_async_op_t;

/** Asynchronous operation context
 *
 * This type represents an asynchronous operation. It stores the state
 * of the operation as well as any necessary parameter and setting.
 * Call mbedtls_async_alloc() to allocate an object of this type.
 *
 * Each context object has a class which is given by the methods in
 * the object of type \c mbedtls_async_info_t passed to mbedtls_async_alloc()
 * when the object is created.
 *
 * At any given time, a context is in one of the following states:
 * - INIT: the initial state after allocation. The application may access
 *   the object as it sees fit.
 * - STARTED: an operation is in progress. In this state, the application should
 *   not modify the object or attempt to access the output.
 * - CANCELLED: like STARTED, but the application has requested the cancellation
 *   of the operation.
 * - DETACHED: like CANCELLED, but the application has requested for the
 *   context object to be freed when the operation completes. The application
 *   may not access the context any longer.
 * - COMPLETED: the context contains the result of an operation. The
 *   application may access the object as it sees fit.
 */
typedef struct mbedtls_async_context mbedtls_async_context_t;

/** Asynchronous operation methods
 *
 * This type represents the methods on an asynchronous operation context.
 * Each implementation of an asynchronous operation context should provide
 * such a method structure. The method structure must remain valid during
 * the lifetime of all the contexts with this method structure; it is normally
 * a static object.
 */
typedef struct mbedtls_async_info mbedtls_async_info_t;

/* fake info for always-synchronous operations */
const mbedtls_async_info_t mbedtls_async_synchronous_info;

/**@}*/



/** \name Functions for callers of asynchronous operations */
/**@{*/

/** Detach from an asynchronous context
 *
 * Detach from the asynchronous context. You may call this function with
 * a valid context in any state. After calling this function, you may not
 * attempt to access the context any longer. The context and all associated
 * resources will be freed as soon as possible.
 */
void mbedtls_async_release( mbedtls_async_context_t *async );

/** Request cancellation
 *
 * Request the cancellation of the ongoing operation in the specified
 * context. The context should be in STARTED state. If the context is in the
 * COMPLETED or CANCELLED state, this function has no effect.
 *
 * \param async         Asynchronous context
 * \return              Status of the operation.
 *
 *                      - \c MBEDTLS_ERR_ASYNC_IN_PROGRESS if the operation
 *                        is still in progress (it is then in the state
 *                        CANCELLED);
 *                      - \c MBEDTLS_ERR_ASYNC_BAD_STATE if the operation
 *                        was not in a valid state for this function;
 *                      - \c MBEDTLS_ERR_ASYNC_CANCELLED if the operation
 *                        has completed after being cancelled (it is then in
 *                        the state COMPLETED);
 *                      - any other error code if the operation had completed
 *                        before the cancellation request was taken into
 *                        account.
 *
 * \note                The intent of cancellation is to notify the
 *                      implementation that the caller no longer cares about
 *                      the result of the operation and no more resources
 *                      should be used to perform it. However, not all
 *                      implementations of asynchronous operations support
 *                      effective cancellation: on some implementations, this
 *                      may be a no-op.
 *
 * \note                After this function returns, the output buffer is
 *                      no longer valid. Implementations must check that
 *                      the operation has not been cancelled before
 *                      accessing the output buffer.
 */
int mbedtls_async_cancel( mbedtls_async_context_t *async );

/** Try making progress
 *
 * This is an informational request to make progress on an ongoing operation.
 * Depending on the nature of the operation, this may poll for a result,
 * apply processor time towards the completion of the operation, or be a
 * no-op.
 *
 * This function does nothing if the operation has already completed.
 *
 * \param async         Asynchronous context, which should be in STARTED
 *                      or CANCELLED state
 * \return              Status of the operation.
 */
int mbedtls_async_resume( mbedtls_async_context_t *async );

/** Reset an asynchronous state
 *
 * Reset an asynchronous state, making it available for a new operation.
 * The context should be in COMPLETED state and will switch to INIT state.
 * If the context is already in INIT state, this function has no effect.
 *
 * \param async         Asynchronous context, which should be in COMPLETED state
 * \return              0 for success,
 *                      or MBEDTLS_ERR_ASYNC_BAD_STATE if the context is
 *                      in an invalid state
 */
int mbedtls_async_reset( mbedtls_async_context_t *async );

/** Get the current status of an asynchronous operation
 *
 * \param async         Asynchronous context
 * \return              Status of the operation:
 *
 *                      - MBEDTLS_ERR_ASYNC_BAD_STATE if no operation is
 *                        set up (state INIT)
 *                      - MBEDTLS_ERR_ASYNC_IN_PROGRESS if the operation is
 *                        in progress (state STARTED or CANCELLED)
 *                      - any other status if the operation is completed
 *                        (state COMPLETED)
 */
int mbedtls_async_status( mbedtls_async_context_t *async );

/** Get the type of the operation
 *
 * \param async         Asynchronous context
 * \return              \c MBEDTLS_PK_OP_NULL if no operation is set up
 *                      (state INIT),
 *                      or another \c MBEDTLS_PK_OP_XXX value indicating what
 *                      type of operation is ongoing (state STARTED,
 *                      CANCELLED or COMPLETED).
 */
mbedtls_async_op_t mbedtls_async_operation_type( const mbedtls_async_context_t *async );

/** Get output length
 *
 * Get the output length from a completed operation.
 *
 * \param async         Asynchronous context, which should be in COMPLETED state
 * \return              Size of the output in bytes
 */
size_t mbedtls_async_get_output_length( const mbedtls_async_context_t *async );

/** Asynchronous operation cookie
 *
 * A cookie is a value that is stored in an asynchronous context to allow the
 * application to track what a context is used for. Typically, when the
 * application learns that an operation has completed, it retrieves the cookie
 * and uses the value to resume processing in the part of the system that was
 * waiting for the result of the operation.
 *
 * Typically the \c type field identifies the type of the subsystem or the
 * class of the object that is waiting for the operation to complete, and the
 * \c instance field identifies the specific subsystem or object. However the
 * application may use this field as it sees fit.
 */
typedef struct
{
    uintptr_t type;
    uintptr_t instance;
} mbedtls_async_cookie_t;

/* Get cookie
 *
 * Retrieve the cookie from an asynchronous operation context.
 *
 * \param async         Asynchronous context
 * \return              Value last set by mbedtls_async_set_cookie(). If this
 *                      function has never been called, return the default
 *                      cookie value, which is all-zero.
 */
mbedtls_async_cookie_t mbedtls_async_get_cookie(
    const mbedtls_async_context_t *async );

/* Set cookie
 *
 * Set the cookie in an asynchronous operation context.
 *
 * \param async         Asynchronous context, which must be in the state INIT
 * \param cookie        New cookie value
 */
void mbedtls_async_set_cookie( mbedtls_async_context_t *async,
                               mbedtls_async_cookie_t cookie );

/**@}*/



/** \name Functions for implementers of asynchronous operations */
/**@{*/

struct mbedtls_async_info
{
    /** Free the custom resources in an asynchronous context
     *
     * This function is called immediately before the context is freed.
     * It is guaranteed that there will not be an operation in progress,
     * i.e. the context is in INIT or COMPLETED state. Typically this
     * function frees the private data of the context.
     *
     * If this function is null, freeing the context just frees the
     * \c mbedtls_async_context_t structure.
     */
    void (*free)( mbedtls_async_context_t *async );

    /** Request the cancellation of the operation
     *
     * mbedtls_async_cancel() calls this function. It is typically used to
     * notify the subsystem that is executing the operation that the result
     * will no longer be needed. This function may update the context to
     * mark it as completed, if the cancellation can be performed
     * synchronously. This function must not block. If this function is null,
     * cancellation has no practical effect.
     */
    void (*cancel)( mbedtls_async_context_t *async );

    /** Attempt to make progress on an asychronous operation
     *
     * mbedtls_async_resume() calls this function. It may be used to
     * provide processor time to perform the operation, or to attempt to
     * retrieve a result. If this function is null, which is common when
     * the operation is performed by an external system that is outside of
     * the control of the application using Mbed TLS, then
     * mbedtls_async_resume() has no effect.
     */
    void (*progress)( mbedtls_async_context_t *async );
};

/** Allocate an asynchronous context
 *
 * This function is usually called by an implementation-dependent wrapper
 * which takes additional parameters and fills the context object accordingly.
 * It may be called directly by application code if so directed by the
 * implementation documentation.
 *
 * \param info          Class of the context (array of methods)
 * \return              A new context object, or NULL if there is not
 *                      enough memory.
 *
 * \note                To free the object, call mbedtls_async_detach().
 */
mbedtls_async_context_t *mbedtls_async_alloc( const mbedtls_async_info_t *info );

/** Set output buffer
 *
 * Set the output buffer in an asynchronous context structure.
 *
 * \param async         Asynchronous context, which must be in the state INIT
 * \param buf           Pointer to the first byte of the output buffer
 * \param size          Size of the output buffer in bytes
 * \return              0 for success,
 *                      or MBEDTLS_ERR_ASYNC_BAD_STATE if the context is
 *                      in an invalid state
 *
 * \note                The output buffer must remain valid until the operation
 *                      completes or is cancelled.
 */
int mbedtls_async_set_output_buffer( mbedtls_async_context_t *async,
                                     void *buf, size_t size );

/** Mark asynchronous context as started
 *
 * Set an asynchronous context's state to STARTED. The context must initially
 * be in the state INIT.
 *
 * This function is meant to be called by implementers of asynchronous
 * contexts as part of starting an asynchronous operation. Do not call it
 * directly from application code, use the functions provided by the
 * asynchronous context implementation.
 *
 * \param async         Asynchronous context, which must be in the state INIT
 * \param op            Type of operation that is starting
 * \return              0 for success,
 *                      or MBEDTLS_ERR_ASYNC_BAD_STATE if the context is
 *                      in an invalid state
 */
int mbedtls_async_set_started( mbedtls_async_context_t *async,
                               mbedtls_async_op_t op );

/** Mark asynchronous context as completed
 *
 * Set an asynchronous context's state to STARTED. The context must initially
 * be in the state INIT.
 *
 * This function is meant to be called by implementers of asynchronous
 * contexts once the results of an asynchronous operation are available.
 *
 * \param async         Asynchronous context, which must be in the state
 *                      STARTED, CANCELLED or DETACHED
 * \param status        Status of the operation. This can be 0 for success
 *                      or any value other to indicate an error. Do not set the
 *                      status to MBEDTLS_ERR_ASYNC_ALLOC_FAILED,
 *                      \c MBEDTLS_ERR_ASYNC_BAD_STATE,
 *                      or \c MBEDTLS_ERR_ASYNC_IN_PROGRESS as these are
 *                      reserved for the operation of the asynchronous
 *                      context itself. Use \c MBEDTLS_ERR_ASYNC_CANCELLED
 *                      only if the application has requested cancellation and
 *                      the operation has not been completed.
 * \param output_length Number of bytes written to the output buffer
 * \return              0 for success,
 *                      or MBEDTLS_ERR_ASYNC_BAD_STATE if the context is
 *                      in an invalid state
 */
int mbedtls_async_set_completed( mbedtls_async_context_t *async,
                                 int status,
                                 size_t output_length );

/* get private data */
void *mbedtls_async_get_data( const mbedtls_async_context_t *async,
                              const mbedtls_async_info_t *info );

/* set private data */
void mbedtls_async_set_data( mbedtls_async_context_t *async,
                             const mbedtls_async_info_t *info,
                             void *data );

/** Lock the output buffer
 *
 * Lock the output buffer for access and return its address and size.
 * The output buffer is valid only an ongoing operation that has not been
 * cancelled, i.e. if the context is in the STARTED state.
 *
 * \param async         Asynchronous context
 * \param size          On success, write the size of the output buffer in bytes.
 * \param buf           On success, write the address of the output buffer.
 * \return              0 if successful,
 *                      \c MBEDTLS_ERR_ASYNC_BAD_STATE or
 *                      \c MBEDTLS_ERR_THREADING_XXX on error
 *
 * \note                If this function succeeds, you must call
 *                      mbedtls_async_unlock_output() in the same thread
 *                      **without blocking**.
 *
 * \note                You may not call any function in this module
 *                      on the same context in the same thread between
 *                      a call to mbedtls_async_lock_output() and the
 *                      subsequent call to mbedtls_async_unlock_output().
 */
int mbedtls_async_lock_output( mbedtls_async_context_t *async,
                               void **buf, size_t *size );

/** Unlock the output buffer
 *
 * After calling mbedtls_async_lock_output() and getting a successful result,
 * you must call this function from the same thread without blocking.
 * Any other use is a programmer error.
 *
 * \param async         Asynchronous context on which you have previously
 *                      called mbedtls_async_lock_output() successfully
 */
void mbedtls_async_unlock_output( mbedtls_async_context_t *async );

/**@}*/

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_ASYNC_H */
