/* psasim test client */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <stdio.h>
#include <unistd.h>

/* Includes from psasim */
#include <psa/client.h>
#include <psa/util.h>
#include "psa_manifest/sid.h"
#include "psa_functions_codes.h"

/* Includes from mbedtls */
#include "mbedtls/version.h"
#include "psa/crypto.h"

#define CLIENT_PRINT(fmt, ...) \
    PRINT("Client: " fmt, ##__VA_ARGS__)

int main()
{
    char mbedtls_version[18];
    // psa_invec invecs[1];
    // psa_outvec outvecs[1];
    psa_status_t status;

    mbedtls_version_get_string_full(mbedtls_version);
    CLIENT_PRINT("%s", mbedtls_version);

    CLIENT_PRINT("My PID: %d", getpid());

    CLIENT_PRINT("PSA version: %u", psa_version(PSA_SID_SHA256_SID));
    psa_handle_t h = psa_connect(PSA_SID_SHA256_SID, 1);

    if (h < 0) {
        CLIENT_PRINT("Couldn't connect %d", h);
        return 1;
    }

    status = psa_call(h, PSA_CRYPTO_INIT, NULL, 0, NULL, 0);
    CLIENT_PRINT("PSA_CRYPTO_INIT returned: %d", status);

    CLIENT_PRINT("Closing handle");
    psa_close(h);

    if (status != PSA_SUCCESS) {
        return 1;
    }
    return 0;
}
