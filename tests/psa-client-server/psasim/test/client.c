/* psasim test client */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <psa/client.h>
#include <psa/util.h>
#include "psa_manifest/sid.h"
#include <stdio.h>
#include <unistd.h>

#define CLIENT_PRINT(fmt, ...) \
    PRINT("Client: " fmt, ##__VA_ARGS__)

int main()
{
    const char *text = "FOOBARCOOL!!";
    char output[100] = { 0 };
    CLIENT_PRINT("My PID: %d", getpid());

    CLIENT_PRINT("PSA version: %u", psa_version(PSA_SID_SHA256_SID));
    psa_handle_t h = psa_connect(PSA_SID_SHA256_SID, 1);

    if (h < 0) {
        CLIENT_PRINT("Couldn't connect %d", h);
        return 1;
    } else {
        int type = 2;
        CLIENT_PRINT("psa_call() w/o invec returned: %d", psa_call(h, type, NULL, 0, NULL, 0));
        psa_invec invecs[1];
        psa_outvec outvecs[1];
        invecs[0].base = text;
        invecs[0].len = sizeof(text);
        outvecs[0].base = output;
        outvecs[0].len = sizeof(output);

        CLIENT_PRINT("invec len: %lu", invecs[0].len);
        CLIENT_PRINT("psa_call() w/ invec returned: %d", psa_call(h, type, invecs, 1, outvecs, 1));
        CLIENT_PRINT("Received payload len: %ld", outvecs[0].len);
        CLIENT_PRINT("Received payload content: %s", output);
        CLIENT_PRINT("Closing handle");
        psa_close(h);
    }

    return 0;
}
