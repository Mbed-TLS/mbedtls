/* psasim test client */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <psa/client.h>
#include "psa_manifest/sid.h"
#include <stdio.h>
#include <unistd.h>

int main()
{

    const char *text = "FOOBARCOOL!!";

    char output[100] = { 0 };
    printf("My PID is %d\n", getpid());

    printf("The version of the service is %u\n", psa_version(PSA_SID_SHA256_SID));
    psa_handle_t h = psa_connect(PSA_SID_SHA256_SID, 1);

    if (h < 0) {
        printf("Couldn't connect %d\n", h);
        return 1;
    } else {
        int type = 2;
        puts("Calling!");
        puts("Trying without invec");
        printf("Answer to my call was %d (no invec)\n", psa_call(h, type, NULL, 0, NULL, 0));
        psa_invec invecs[1];
        psa_outvec outvecs[1];
        invecs[0].base = text;
        invecs[0].len = 24;
        outvecs[0].base = output;
        outvecs[0].len = 99;

        printf("My iovec size should be %lu\n", invecs[0].len);
        printf("Answer to my call was %d (with invec)\n", psa_call(h, type, invecs, 1, outvecs, 1));
        printf("Here's the payload I recieved: %s\n", output);
        printf("Apparently the server wrote %lu bytes in outvec %d\n", outvecs[0].len, 0);
        puts("Closing handle");
        psa_close(h);
    }

    return 0;
}
