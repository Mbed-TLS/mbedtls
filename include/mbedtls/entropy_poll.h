/**
 * \file entropy_poll.h
 *
 * \brief Platform-specific and custom entropy polling functions
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_ENTROPY_POLL_H
#define MBEDTLS_ENTROPY_POLL_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Default thresholds for built-in sources
 */
#define MBEDTLS_ENTROPY_MIN_PLATFORM    128     /**< Minimum for platform source    */
#define MBEDTLS_ENTROPY_MIN_HAVEGE      128     /**< Minimum for HAVEGE             */
#define MBEDTLS_ENTROPY_MIN_HARDCLOCK    32     /**< Minimum for mbedtls_timing_hardclock()        */

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
/**
 * \brief           Platform-specific entropy poll callback
 */
int mbedtls_platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen );
#endif

#if defined(MBEDTLS_HAVEGE_C)
/**
 * \brief           HAVEGE based entropy poll callback
 *
 * Requires an HAVEGE state as its data pointer.
 */
int mbedtls_havege_poll( void *data,
                 unsigned char *output, size_t len, size_t *olen );
#endif

#if defined(MBEDTLS_TIMING_C)
/**
 * \brief           mbedtls_timing_hardclock-based entropy poll callback
 */
int mbedtls_hardclock_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen );
#endif

#ifdef __cplusplus
}
#endif

#endif /* entropy_poll.h */
