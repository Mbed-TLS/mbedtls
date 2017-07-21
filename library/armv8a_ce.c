/**
 * \file armv8a_ce.c
 *
 * \brief Compile and runtime checks for ARM features to accelerate crypto
 *
 *  Copyright (C) 2016, CriticalBlue Limited, All Rights Reserved
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/* Check if the module is enabled */
#if defined(MBEDTLS_ARMV8A_CE_C)

#include "mbedtls/aes_armv8a_ce.h"


/* Check if cryptography extensions are supported */
#if defined(MBEDTLS_HAVE_ARMV8A_CE)

#if defined(linux)

/*
 * ARMv8a Cryptography Extension support detection routine for Linux
 */
unsigned long mbedtls_platform_linux_armv8a_ce_get_hwcap(void)
{
	return getauxval(AT_HWCAP);
}

#else

/*
 * ARMv8a Crypto Extension default support detection routine
 */
unsigned long mbedtls_platform_none_armv8a_ce_get_hwcap(void)
{
	return 0;
}

#endif /* linux */

/*
 * ARMv8a Crypto Extension support detection routine
 */
int mbedtls_armv8a_ce_has_support( unsigned int what )
{
    static int done = 0;
    static unsigned int c = 0;

    if ( ! done )
    {
		c = MBEDTLS_PLATFORM_ARMV8A_CE_GET_HWCAP();
        done = 1;
    }

    return ( c & what ) != 0;
}

#endif /* MBEDTLS_HAVE_ARMV8A_CE */

#endif /* MBEDTLS_ARMV8A_CE_C */
