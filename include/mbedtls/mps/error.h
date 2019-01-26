/**
 * \file error.h
 *
 * \brief Message Processing Stack
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

#ifndef MBEDTLS_MPS_ERROR_H
#define MBEDTLS_MPS_ERROR_H

/**
 * MPS-specific error codes
 */
/* TODO: Put proper error code constants in here. */
#define MBEDTLS_ERR_MPS_RETRY_ON_CONDITION    -0x01
#define MBEDTLS_ERR_MPS_NO_FORWARD            -0x02
#define MBEDTLS_ERR_MPS_WRITE_PORT_ACTIVE     -0x03
#define MBEDTLS_ERR_MPS_BLOCKED               -0x04
#define MBEDTLS_ERR_MPS_TIMEOUT               -0x05
#define MBEDTLS_ERR_MPS_INVALID_ALERT         -0x06
#define MBEDTLS_ERR_MPS_FATAL_ALERT           -0x07
#define MBEDTLS_ERR_MPS_INTERNAL_ERROR        -0x08
#define MBEDTLS_ERR_MPS_PORT_NOT_ACTIVE       -0x09
#define MBEDTLS_ERR_MPS_REQUEST_TOO_LARGE     -0x09
#define MBEDTLS_ERR_MPS_DOUBLE_REQUEST        -0x0a
#define MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED -0x0b
#define MBEDTLS_ERR_MPS_OPTION_UNSUPPORTED    -0x0c
#define MBEDTLS_ERR_MPS_OPTION_SET            -0x0d
#define MBEDTLS_ERR_MPS_PARAM_MISSING         -0x0e
#define MBEDTLS_ERR_MPS_PARAM_MISMATCH        -0x0f
#define MBEDTLS_ERR_MPS_UNEXPECTED_FLIGHT     -0x10
#define MBEDTLS_ERR_MPS_NO_PROGRESS           -0x11
#define MBEDTLS_ERR_MPS_NOT_BLOCKED           -0x12
#define MBEDTLS_ERR_MPS_UNTRACKED_DIGEST      -0x13
#define MBEDTLS_ERR_MPS_CLOSE_NOTIFY          -0x14
#define MBEDTLS_ERR_MPS_FATAL_ALERT_RECEIVED  -0x15
#define MBEDTLS_ERR_MPS_BAD_EPOCH             -0x16
#define MBEDTLS_ERR_MPS_BAD_FRAGMENTATION     -0x1b
#define MBEDTLS_ERR_MPS_FLIGHT_RETRANSMISSION -0x17
#define MBEDTLS_ERR_MPS_FLIGHT_TOO_LONG       -0x18
#define MBEDTLS_ERR_MPS_COUNTER_WRAP          -0x1a
#define MBEDTLS_ERR_MPS_OUT_OF_MEMORY         -0x19
#define MBEDTLS_ERR_MPS_REASSEMBLY_PENDING    -0x1b

/*
 * Layer 2 specific error codes
 */

#define MPS_ERR_ALLOC_FAILED           -0x1a /*!< A request for dynamic memory
                                              *  allocation failed.           */
#define MPS_ERR_UNEXPECTED_OPERATION   -0x17 /*!< The requested operation cannot
                                              *  be performed in the current
                                              *  state of the Layer 2 context.*/
#define MPS_ERR_INVALID_CONTENT_MERGE  -0x52
#define MPS_ERR_TYPE_CANT_BE_PAUSED    -0x1b
#define MPS_ERR_PAUSE_REFUSED          -0x18
#define MPS_ERR_MULTIPLE_PAUSING       -0x19
#define MPS_ERR_COUNTER_WRAP           -0x15 /*!< The record sequence number be increased
                                              *   because it would wrap.                   */
#define MPS_ERR_REPLAYED_RECORD        -0x17
#define MPS_ERR_INVALID_ARGS           -0x28 /*!< The parameter validation failed.         */
#define MPS_ERR_INVALID_RECORD         -0x321  /*!< The record header is invalid.            */
#define MPS_ERR_INVALID_MAC            -0x33  /*!< The record MAC is invalid.               */
#define MPS_ERR_INVALID_EPOCH          -0x42  /*!< The record header is invalid.            */
#define MPS_ERR_EPOCH_CHANGE_REJECTED  -0x6  /*!< The current epoch couldn't be changed.   */
#define MPS_ERR_EPOCH_ALREADY_SET      -0x7  /*!< The epoch under consideration has already
                                              *   been configured.                         */
#define MPS_ERR_EPOCH_WINDOW_EXCEEDED  -0x7  /*!< The epoch under consideration exceeds the
                                              *   current epoch window.                    */
#define MPS_ERR_EPOCH_OVERFLOW         -0xa  /*!< The epoch under consideration exceeds the
                                              *   current epoch window.                    */
#define MPS_ERR_CONTINUE_PROCESSING    -0x123
#define MPS_ERR_BAD_TRANSFORM          -0x124

/*
 * Error codes
 */

#define MPS_ERR_EOF                   -0x01
#define MPS_ERR_WANT_READ             -0x02 /*!< The underlying transport
                                             *   does not have enough incoming
                                             *   data available to perform the
                                             *   requested read operation.    */
#define MPS_ERR_WANT_WRITE            -0x03 /*!< The underlying transport is
                                             *   unavailable perform the
                                             *   request send operation.      */
#define MPS_ERR_NO_DATA               -0x7
#define MPS_ERR_UNSUPPORTED_FEATURE   -0x12
#define MPS_ERR_BUFFER_TOO_SMALL      -0x13
#define MPS_ERR_INTERNAL_ERROR        -0x14
#define MPS_ERR_REQUEST_OUT_OF_BOUNDS -0x15
#define MPS_ERR_INVALID_PARAMS        -0x16
#define MPS_ERR_UNEXPECTED_OPERATION  -0x17
#define MPS_ERR_INCONSISTENT_READ     -0x18

/*
 * Layer 3 specific error codes
 */

#define MPS_ERR_INCONSISTENT_ARGS -0x123 /*!< The handshake parameters don't
                                          *   match those from the currently
                                          *   paused outgoing handshake
                                          *   message.                       */
#define MPS_ERR_NO_INTERLEAVING   -0x124 /*!< A request was made to send
                                          *   non-handshake data while an
                                          *   an outgoing handshake message
                                          *   was paused.                    */
#define MPS_ERR_UNFINISHED_HS_MSG -0x112 /*!< A request was made to finish
                                          *   the writing of a handshake
                                          *   message before as much data had
                                          *   been written to it as indicated
                                          *   in the handshake message length
                                          *   specified in the initial call
                                          *   to mps_l3_write_handshake().   */
#define MPS_ERR_BAD_MSG           -0x124 /*!< A handshake message with invalid
                                              handshake header was received. */

/* TODO: Integrate MPS error codes with rest of the library. */
#define MPS_ERR_ALLOC_OUT_OF_SPACE    0x1
#define MPS_ERR_ALLOC_NOT_ALLOCATED   0x2
#define MPS_ERR_ALLOC_INVALID_PURPOSE 0x3

#endif /* MBEDTLS_MPS_ERROR_H */
