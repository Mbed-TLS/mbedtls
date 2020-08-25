/*
 *  Hardware entropy collector for the K64F, using Freescale's RNGA
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 *  This file is provided under the Apache License 2.0, or the
 *  GNU General Public License v2.0 or later.
 *
 *  **********
 *  Apache License 2.0:
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
 *  **********
 *
 *  **********
 *  GNU General Public License v2.0 or later:
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
 *
 *  **********
 */

/*
 * WARNING: this is temporary!
 * This should be in a separate yotta module which would be a target
 * dependency of mbedtls (see IOTSSL-313)
 */

#if defined(TARGET_LIKE_K64F)

/*
 * Reference: "K64 Sub-Family Reference Manual, Rev. 2", chapter 34
 */

#include "fsl_clock_manager.h"

/*
 * Get one byte of entropy from the RNG, assuming it is up and running.
 * As recommended (34.1.1), get only one bit of each output.
 */
static void rng_get_byte( unsigned char *byte )
{
    size_t bit;

    /* 34.5 Steps 3-4-5: poll SR and read from OR when ready */
    for( bit = 0; bit < 8; bit++ )
    {
        while( ( RNG->SR & RNG_SR_OREG_LVL_MASK ) == 0 );
        *byte |= ( RNG->OR & 1 ) << bit;
    }
}

/*
 * Get len bytes of entropy from the hardware RNG.
 */
int mbedtls_hardware_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen )
{
    size_t i;
    int ret;
    ((void) data);

    CLOCK_SYS_EnableRngaClock( 0 );

    /* Set "Interrupt Mask", "High Assurance" and "Go",
     * unset "Clear interrupt" and "Sleep" */
    RNG->CR = RNG_CR_INTM_MASK | RNG_CR_HA_MASK | RNG_CR_GO_MASK;

    for( i = 0; i < len; i++ )
        rng_get_byte( output + i );

    /* Just be extra sure that we didn't do it wrong */
    if( ( RNG->SR & RNG_SR_SECV_MASK ) != 0 )
    {
        ret = -1;
        goto cleanup;
    }

    *olen = len;
    ret = 0;

cleanup:
    /* Disable clock to save power - assume we're the only users of RNG */
    CLOCK_SYS_DisableRngaClock( 0 );

    return( ret );
}

#endif
