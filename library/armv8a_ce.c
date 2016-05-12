/*
 * armv8a_ce.c
 *
 *  Created on: 9 May 2016
 *      Author: johanness
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/* Check if the module is enabled */
#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_ARMV8A_CE_C)
#include "mbedtls/aes_armv8a_ce.h"

/* Check if crypto is supported */
#if defined(MBEDTLS_HAVE_ARMV8A_CE)

/*
 * ARMv8a Crypto Extension support detection routine
 */
int mbedtls_armv8a_ce_has_support( unsigned int what )
{
    static int done = 0;
    static unsigned int c = 0;

    if( ! done )
    {
    	c = getauxval(AT_HWCAP);
        done = 1;
    }

    return( ( c & what ) != 0 );
}

#endif /* MBEDTLS_HAVE_ARMV8A_CE */

