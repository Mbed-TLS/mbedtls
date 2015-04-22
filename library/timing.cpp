/*
 *  Timing functions for mbed TLS on top of mbed OS
 *
 *  Copyright (C) 2014, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#if defined(MBEDTLS_TIMING_C) && !defined(MBEDTLS_TIMING_ALT)

#include "mbedtls/timing.h"

#include "mbed.h"

#if defined(TARGET_LIKE_CORTEX_M4)

#include "core_cm4.h"

unsigned long mbedtls_timing_hardclock( void )
{
    static int dwt_started = 0;

    if( dwt_started == 0 )
    {
        CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
        DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    }

    return( DWT->CYCCNT );
}

#else
unsigned long mbedtls_timing_hardclock( void )
{
    /* dummy implementation that fails in a visible way */
    return( 0 );
}
#endif

unsigned long mbedtls_timing_get_timer( struct mbedtls_timing_hr_time *val, int reset )
{
    Timer *t = reinterpret_cast<Timer *>( val );

    if( sizeof( struct mbedtls_timing_hr_time ) < sizeof( Timer ) )
    {
        mbedtls_printf( "You got bitten by your dirty hack.\r\n" );
        while( 1 )
            ;
    }

    if( reset )
    {
        t->reset();
        t->start();
        return( 0 );
    }

    return( t->read_ms() );
}

void mbedtls_timing_m_sleep( int milliseconds )
{
    wait_ms( milliseconds );
}

volatile int mbedtls_timing_alarmed = 0;

static void alarm_handler( void )
{
    mbedtls_timing_alarmed = 1;
}

static Timeout alarm_setter;

void mbedtls_set_alarm( int seconds )
{
    mbedtls_timing_alarmed = 0;
    alarm_setter.attach( alarm_handler, seconds );
}

#if defined(MBEDTLS_SELF_TEST)

/* To test mbedtls_net_usleep against our functions */
#if defined(MBEDTLS_NET_C) && defined(MBEDTLS_HAVE_TIME)
#include "mbedtls/net.h"
#endif

/*
 * Busy-waits for the given number of milliseconds.
 * Used for testing mbedtls_timing_hardclock.
 */
static void busy_msleep( unsigned long msec )
{
    struct mbedtls_timing_hr_time hires;
    unsigned long i = 0; /* for busy-waiting */
    volatile unsigned long j; /* to prevent optimisation */

    (void) mbedtls_timing_get_timer( &hires, 1 );

    while( mbedtls_timing_get_timer( &hires, 0 ) < msec )
        i++;

    j = i;
    (void) j;
}

/*
 * Checkup routine
 *
 * Warning: this is work in progress, some tests may not be reliable enough
 * yet! False positives may happen.
 */
int mbedtls_timing_self_test( int verbose )
{
    unsigned long cycles, ratio;
    unsigned long millisecs, secs;
    int hardfail;
    struct mbedtls_timing_hr_time hires;

    if( verbose != 0 )
        mbedtls_printf( "  TIMING tests note: will take some time!\r\n" );

    if( verbose != 0 )
        mbedtls_printf( "  TIMING test #1 (m_sleep   / get_timer): " );

    for( secs = 1; secs <= 3; secs++ )
    {
        (void) mbedtls_timing_get_timer( &hires, 1 );

        mbedtls_timing_m_sleep( (int)( 500 * secs ) );

        millisecs = mbedtls_timing_get_timer( &hires, 0 );

        if( millisecs < 450 * secs || millisecs > 550 * secs )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\r\n" );

            return( 1 );
        }
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\r\n" );

    if( verbose != 0 )
        mbedtls_printf( "  TIMING test #2 (set_alarm / get_timer): " );

    for( secs = 1; secs <= 3; secs++ )
    {
        (void) mbedtls_timing_get_timer( &hires, 1 );

        mbedtls_set_alarm( (int) secs );
        while( !mbedtls_timing_alarmed )
            ;

        millisecs = mbedtls_timing_get_timer( &hires, 0 );

        if( millisecs < 900 * secs || millisecs > 1100 * secs )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\r\n" );

            return( 1 );
        }
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\r\n" );

    if( verbose != 0 )
        mbedtls_printf( "  TIMING test #3 (hardclock / get_timer): " );

    /*
     * Allow one failure for possible counter wrapping.
     * On a 4Ghz 32-bit machine the cycle counter wraps about once per second;
     * since the whole test is about 10ms, it shouldn't happen twice in a row.
     */
    hardfail = 0;

hard_test:
    if( hardfail > 1 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\r\n" );

        return( 1 );
    }

    /* Get a reference ratio cycles/ms */
    millisecs = 1;
    cycles = mbedtls_timing_hardclock();
    busy_msleep( millisecs );
    cycles = mbedtls_timing_hardclock() - cycles;
    ratio = cycles / millisecs;

    /* Check that the ratio is mostly constant */
    for( millisecs = 2; millisecs <= 4; millisecs++ )
    {
        cycles = mbedtls_timing_hardclock();
        busy_msleep( millisecs );
        cycles = mbedtls_timing_hardclock() - cycles;

        /* Allow variation up to 20% */
        if( cycles / millisecs < ratio - ratio / 5 ||
            cycles / millisecs > ratio + ratio / 5 )
        {
            hardfail++;
            goto hard_test;
        }
    }

    if( verbose != 0 )
        mbedtls_printf( "passed (%lu MHz)\r\n", ratio / 1000 );

#if defined(MBEDTLS_NET_C) && defined(MBEDTLS_HAVE_TIME)
    if( verbose != 0 )
        mbedtls_printf( "  TIMING test #4 (net_usleep/ get_timer): " );

    for( secs = 1; secs <= 3; secs++ )
    {
        (void) mbedtls_timing_get_timer( &hires, 1 );

        mbedtls_net_usleep( 500000 * secs );

        millisecs = mbedtls_timing_get_timer( &hires, 0 );

        if( millisecs < 450 * secs || millisecs > 550 * secs )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\r\n" );

            return( 1 );
        }
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\r\n" );
#endif /* MBEDTLS_NET_C */

    if( verbose != 0 )
        mbedtls_printf( "\r\n" );

    return( 0 );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_TIMING_C && !MBEDTLS_TIMING_ALT */
