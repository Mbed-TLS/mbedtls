/**
 * Copyright (C) 2014 Virgil Security Inc.
 *
 * This file is part of extension to mbed TLS (http://www.polarssl.org)
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_KDF_C)

#include "polarssl/kdf.h"
#include "polarssl/kdf_wrap.h"

#include <stdlib.h>

#if defined(_MSC_VER) && !defined strcasecmp && !defined(EFIX64) && \
    !defined(EFI32)
#define strcasecmp  _stricmp
#endif

static const int supported_kdfs[] = {

#if defined(POLARSSL_KDF1_C)
        POLARSSL_KDF_KDF1,
#endif

#if defined(POLARSSL_KDF2_C)
        POLARSSL_KDF_KDF2,
#endif
        POLARSSL_KDF_NONE
};

const int *kdf_list( void )
{
    return( supported_kdfs );
}

const kdf_info_t *kdf_info_from_string( const char *kdf_name )
{
    if( NULL == kdf_name )
        return( NULL );

    /* Get the appropriate key derivation function information */
#if defined(POLARSSL_KDF1_C)
    if( !strcasecmp( "KDF1", kdf_name ) )
        return kdf_info_from_type( POLARSSL_KDF_KDF1 );
#endif
#if defined(POLARSSL_KDF2_C)
    if( !strcasecmp( "KDF2", kdf_name ) )
        return kdf_info_from_type( POLARSSL_KDF_KDF2 );
#endif
    return( NULL );
}

const kdf_info_t *kdf_info_from_type( kdf_type_t kdf_type )
{
    switch( kdf_type )
    {
#if defined(POLARSSL_KDF1_C)
        case POLARSSL_KDF_KDF1:
            return( &kdf1_info );
#endif
#if defined(POLARSSL_KDF2_C)
        case POLARSSL_KDF_KDF2:
            return( &kdf2_info );
#endif
        default:
            return( NULL );
    }
}


int kdf( const kdf_info_t *kdf_info, const md_info_t *md_info, const unsigned char *input, size_t ilen,
            unsigned char *output, size_t olen)
{
    int res = 0;

    if( kdf_info == NULL )
        return( POLARSSL_ERR_KDF_BAD_INPUT_DATA );

    if ( ( res = kdf_info->kdf( md_info, input, ilen, output, olen ) ) != 0 )
    {
        return POLARSSL_ERR_KDF_BAD_INPUT_DATA | res;
    }
    return 0;
}

#endif /* POLARSSL_KDF_C */
