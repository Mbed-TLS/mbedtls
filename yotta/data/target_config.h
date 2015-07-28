/*
 *  Temporary target-specific config.h for entropy collection
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if defined(TARGET_LIKE_MBED)
#define MBEDTLS_NO_PLATFORM_ENTROPY
#undef MBEDTLS_HAVE_TIME_DATE
#undef MBEDTLS_FS_IO
#endif

/*
 * WARNING: this is a temporary hack!
 * 2. This should be in a separete yotta module which would be a target
 * dependency of mbedtls (see IOTSSL-313)
 */
#if defined(TARGET_LIKE_CORTEX_M4)
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#endif
