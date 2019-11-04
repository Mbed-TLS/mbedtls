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

#ifndef MBEDTLS_MPS_ERR_BASE
#define MBEDTLS_MPS_ERR_BASE 0
#endif

#define MBEDTLS_MPS_MAKE_ERROR(code) \
    ( -( MBEDTLS_MPS_ERR_BASE | (code) ) )

/*
 * Error codes visible at the MPS boundary.
 */

/*! A request for dynamic memory allocation failed. */
#define MBEDTLS_ERR_MPS_OUT_OF_MEMORY         MBEDTLS_MPS_MAKE_ERROR( 0x0e )
/*! The requested operation is not supported. */
#define MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED MBEDTLS_MPS_MAKE_ERROR( 0x06 )
/*! The requested operation cannot be performed in the current state. */
#define MBEDTLS_ERR_MPS_OPERATION_UNEXPECTED  MBEDTLS_MPS_MAKE_ERROR( 0x10 )
/*! The peer has sent a closure notification alert. */
#define MBEDTLS_ERR_MPS_CLOSE_NOTIFY          MBEDTLS_MPS_MAKE_ERROR( 0x07 )
/*! The MPS is blocked. */
#define MBEDTLS_ERR_MPS_BLOCKED               MBEDTLS_MPS_MAKE_ERROR( 0x02 )
/*! The peer has sent an unknown non-fatal alert and MPS
 *  is configured to treat this as fatal. */
#define MBEDTLS_ERR_MPS_UNKNOWN_ALERT         MBEDTLS_MPS_MAKE_ERROR( 0x03 )
/*! The peer has sent a fatal alert. */
#define MBEDTLS_ERR_MPS_FATAL_ALERT_RECEIVED  MBEDTLS_MPS_MAKE_ERROR( 0x08 )
/*! An internal assertion has failed - should never happen. */
#define MBEDTLS_ERR_MPS_INTERNAL_ERROR        MBEDTLS_MPS_MAKE_ERROR( 0x05 )
#define MBEDTLS_ERR_MPS_RETRY                 MBEDTLS_MPS_MAKE_ERROR( 0x11 )
#define MBEDTLS_ERR_MPS_NO_FORWARD            MBEDTLS_ERR_MPS_RETRY
#define MBEDTLS_ERR_MPS_COUNTER_WRAP          MBEDTLS_MPS_MAKE_ERROR( 0x0d )
#define MBEDTLS_ERR_MPS_FLIGHT_TOO_LONG       MBEDTLS_MPS_MAKE_ERROR( 0x0c )
/*! MPS cannot handle the amount of record fragmentation used by the peer.
 *  This happens e.g. if fragmented handshake records are interleaved with
 *  fragmented alert records. */
#define MBEDTLS_ERR_MPS_EXCESS_RECORD_FRAGMENTATION  MBEDTLS_MPS_MAKE_ERROR( 0x12 )
/*! Layer 2 has been asked to pause a non-pausable record type. */
#define MBEDTLS_ERR_MPS_INVALID_RECORD_FRAGMENTATION MBEDTLS_MPS_MAKE_ERROR( 0x13 )
/*! The epoch under consideration exceeds the current epoch window. */
#define MBEDTLS_ERR_MPS_TOO_MANY_LIVE_EPOCHS  MBEDTLS_MPS_MAKE_ERROR( 0x7 )
#define MBEDTLS_ERR_MPS_TOO_MANY_EPOCHS       MBEDTLS_MPS_MAKE_ERROR( 0xa )
/*! The underlying transport does not have enough incoming data available
 *  to perform the requested read operation. */
#define MBEDTLS_ERR_MPS_WANT_READ             MBEDTLS_MPS_MAKE_ERROR( 0x02 )
/*! The underlying transport is unavailable perform the send operation. */
#define MBEDTLS_ERR_MPS_WANT_WRITE            MBEDTLS_MPS_MAKE_ERROR( 0x03 )
#define MBEDTLS_ERR_MPS_BAD_TRANSFORM         MBEDTLS_MPS_MAKE_ERROR( 0x124 )
#define MBEDTLS_ERR_MPS_BUFFER_TOO_SMALL      MBEDTLS_MPS_MAKE_ERROR( 0x13 )
/*! A request was made to send non-handshake data while an
 *  an outgoing handshake message was paused. */
#define MBEDTLS_ERR_MPS_NO_INTERLEAVING       MBEDTLS_MPS_MAKE_ERROR( 0x124 )
/*! A request was made to finish the writing of a handshake
 *  message before as much data had been written to it as indicated
 *  in the handshake message length specified in the initial call
 *  to mps_l3_write_handshake().   */
#define MBEDTLS_ERR_MPS_UNFINISHED_HS_MSG     MBEDTLS_MPS_MAKE_ERROR( 0x112 )
#define MBEDTLS_ERR_MPS_ALLOC_OUT_OF_SPACE    MBEDTLS_MPS_MAKE_ERROR( 0x1 )
#define MBEDTLS_ERR_MPS_ALLOC_NOT_ALLOCATED   MBEDTLS_MPS_MAKE_ERROR( 0x2 )
/*! The parameter validation failed. */
#define MBEDTLS_ERR_MPS_INVALID_ARGS          MBEDTLS_MPS_MAKE_ERROR( 0x18 )
/*! The record header is invalid.
 *  This is only visible on the MPS boundary in TLS. */
#define MBEDTLS_ERR_MPS_INVALID_CONTENT       MBEDTLS_MPS_MAKE_ERROR( 0x19 )
/*! The record header is invalid.
 *  This is only visible on the MPS boundary in TLS. */
#define MBEDTLS_ERR_MPS_INVALID_RECORD        MBEDTLS_MPS_MAKE_ERROR( 0x19 )
/*! The record MAC is invalid.
 *  This is only visible on the MPS boundary in TLS. */
#define MBEDTLS_ERR_MPS_INVALID_MAC           MBEDTLS_MPS_MAKE_ERROR( 0x33 )
/*! The record header is invalid.
 *  This is only visible on the MPS boundary in TLS. */
#define MBEDTLS_ERR_MPS_INVALID_EPOCH         MBEDTLS_MPS_MAKE_ERROR( 0x42 )

/*
 * Internal error codes
 */
#define MBEDTLS_ERR_MPS_FLIGHT_RETRANSMISSION MBEDTLS_MPS_MAKE_ERROR( 0x0b )
#define MBEDTLS_ERR_MPS_REPLAYED_RECORD   MBEDTLS_MPS_MAKE_ERROR( 0x17 )
#define MBEDTLS_ERR_MPS_REQUEST_OUT_OF_BOUNDS MBEDTLS_MPS_MAKE_ERROR( 0x15 )

#endif /* MBEDTLS_MPS_ERROR_H */
