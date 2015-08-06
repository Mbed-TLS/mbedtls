/*
 *  Temporary "entropy" collector for Cortex-M4
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * WARNING: this is a temporary hack!
 * 1. Currently does not provide strong entropy, should be replaced to use the
 * on-board hardware RNG (see IOTSSL-303)
 * 2. This should be in a separete yotta module which would be a target
 * dependency of mbedtls (see IOTSSL-313)
 */

#if defined(TARGET_LIKE_CORTEX_M4)

#include "MK64F12.h"
#include "core_cm4.h"
#include <string.h>

unsigned long hardclock( void )
{
    static int dwt_started = 0;

    if( dwt_started == 0 )
    {
        CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
        DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    }

    return( DWT->CYCCNT );
}

int mbedtls_hardware_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen )
{
    unsigned long timer = hardclock();
    ((void) data);
    *olen = 0;

    if( len < sizeof(unsigned long) )
        return( 0 );

    memcpy( output, &timer, sizeof(unsigned long) );
    *olen = sizeof(unsigned long);

    return( 0 );
}

#endif
