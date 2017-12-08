/**
 * \file async_queue.h
 *
 * \brief Queues of asynchronous operations
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

#ifndef MBEDTLS_ASYNC_QUEUE_H
#define MBEDTLS_ASYNC_QUEUE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "async.h"
#include "pk.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_async_queue_element mbedtls_async_queue_element_t;
typedef struct
{
    mbedtls_async_queue_element_t *head;
    mbedtls_async_queue_element_t *tail;
} mbedtls_async_queue_t;

void mbedtls_async_queue_init( mbedtls_async_queue_t *queue );

void mbedtls_async_queue_free( mbedtls_async_queue_t *queue );

mbedtls_async_context_t *mbedtls_async_queue_add( mbedtls_async_queue_t *queue,
                                                  void *data,
                                                  mbedtls_async_cookie_t cookie );

void mbedtls_async_queue_remove( mbedtls_async_queue_element_t *elt );

mbedtls_async_context_t *mbedtls_async_queue_element_get_data(
    mbedtls_async_queue_element_t *elt );




int mbedtls_pk_setup_queued( mbedtls_pk_context *pk,
                             mbedtls_pk_context *underlying_pk,
                             mbedtls_async_queue_t *queue );

mbedtls_async_context_t *mbedtls_pk_start_queued(
    mbedtls_async_queue_element_t *elt );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_ASYNC_QUEUE_H */
