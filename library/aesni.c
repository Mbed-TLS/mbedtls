/*
 *  AES-NI support functions
 *
 *  Copyright (C) 2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
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

/*
 * [AES-WP] http://software.intel.com/en-us/articles/intel-advanced-encryption-standard-aes-instructions-set
 */

#include "polarssl/config.h"

#if defined(POLARSSL_AESNI_C)

#include "polarssl/aesni.h"

#if defined(POLARSSL_HAVE_X86_64)

/*
 * AES-NI support detection routine, [AES-WP] figure 23
 */
int aesni_supported( void )
{
    static int supported = -1;
    unsigned int c;

    if( supported == -1 )
    {
        asm( "movl  $1, %%eax   \n"
             "cpuid             \n"
             : "=c" (c)
             :
             : "eax", "ebx", "edx" );
        supported = ( ( c & 0x02000000 ) != 0 );
    }

    return( supported );
}

#endif /* POLARSSL_HAVE_X86_64 */

#endif /* POLARSSL_AESNI_C */
