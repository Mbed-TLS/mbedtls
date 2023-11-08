/**
 *  \brief Generate random data into a file
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/platform.h"

#if defined(MBEDTLS_HAVEGE_C) && defined(MBEDTLS_FS_IO)
#include "mbedtls/havege.h"

#include <stdio.h>
#include <time.h>
#endif

#if !defined(MBEDTLS_HAVEGE_C) || !defined(MBEDTLS_FS_IO)
int main(void)
{
    mbedtls_printf("MBEDTLS_HAVEGE_C not defined.\n");
    mbedtls_exit(0);
}
#else


int main(int argc, char *argv[])
{
    FILE *f;
    time_t t;
    int i, k, ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_havege_state hs;
    unsigned char buf[1024];

    if (argc < 2) {
        mbedtls_fprintf(stderr, "usage: %s <output filename>\n", argv[0]);
        mbedtls_exit(exit_code);
    }

    if ((f = fopen(argv[1], "wb+")) == NULL) {
        mbedtls_printf("failed to open '%s' for writing.\n", argv[1]);
        mbedtls_exit(exit_code);
    }

    mbedtls_havege_init(&hs);

    t = time(NULL);

    for (i = 0, k = 768; i < k; i++) {
        if ((ret = mbedtls_havege_random(&hs, buf, sizeof(buf))) != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_havege_random returned -0x%04X",
                           (unsigned int) -ret);
            goto exit;
        }

        fwrite(buf, sizeof(buf), 1, f);

        mbedtls_printf("Generating %ldkb of data in file '%s'... %04.1f" \
                       "%% done\r",
                       (long) (sizeof(buf) * k / 1024),
                       argv[1],
                       (100 * (float) (i + 1)) / k);
        fflush(stdout);
    }

    if (t == time(NULL)) {
        t--;
    }

    mbedtls_printf(" \n ");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    mbedtls_havege_free(&hs);
    fclose(f);
    mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_HAVEGE_C */
