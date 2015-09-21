/*
 *  Temporary "entropy" collector for Cortex-M4
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

/*
 * WARNING: this is a temporary hack!
 * 1. Currently does not provide strong entropy, should be replaced to use the
 * on-board hardware RNG (see IOTSSL-303)
 * 2. This should be in a separete yotta module which would be a target
 * dependency of mbedtls (see IOTSSL-313)
 */

#if defined(TARGET_LIKE_CORTEX_M4)

#if defined(TARGET_K64F)
#include "MK64F12.h"
#elif defined(TARGET_STM32F4)
#warning "NO TRUE ENTROPY SOURCE FOR STM32F4"
#include "stm32f429xx.h"
#else
#error "TRUE ENTROPY SOURCE REQUIRED. NONE DEFINED FOR THIS TARGET."
#endif
#include "core_cm4.h"
#include <string.h>

unsigned long hardclock( void )
{
#if !defined(TARGET_STM32F4)
    static int dwt_started = 0;

    if( dwt_started == 0 )
    {
        CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
        DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    }
#endif
    return( DWT->CYCCNT );
}

int mbedtls_hardware_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen )
{
#if !defined(TARGET_STM32F4)
    unsigned long timer = hardclock();
    ((void) data);
    *olen = 0;

    if( len < sizeof(unsigned long) )
        return( 0 );

    memcpy( output, &timer, sizeof(unsigned long) );
    *olen = sizeof(unsigned long);
#endif
    return( 0 );
}

#endif
