/* psasim test server */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <psa/service.h>
#include "psa_manifest/manifest.h"
#include <unistd.h>
#include <stdio.h>

void printbits(uint32_t num)
{
    for (int i = 0; i < 32; i++) {
        if ((num >> (31-i) & 0x1)) {
            printf("1");
        } else {
            printf("0");
        }
    }
    printf("\n");
}

#define BUF_SIZE 25

int psa_sha256_main()
{
    psa_status_t ret = PSA_ERROR_PROGRAMMER_ERROR;
    psa_msg_t msg = { -1 };
    char foo[BUF_SIZE] = { 0 };
    const int magic_num = 66;

    puts("Starting");

    while (1) {
        puts("Calling psa_wait");
        psa_signal_t signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

        if (signals > 0) {
            printbits(signals);
        }

        if (signals & PSA_SHA256_SIGNAL) {
            puts("Oooh a signal!");

            if (PSA_SUCCESS == psa_get(PSA_SHA256_SIGNAL, &msg)) {
                printf("My handle is %d\n", msg.handle);
                printf("My rhandle is %p\n", (int *) msg.rhandle);
                switch (msg.type) {
                    case PSA_IPC_CONNECT:
                        puts("Got a connection message");
                        psa_set_rhandle(msg.handle, (void *) &magic_num);
                        ret = PSA_SUCCESS;
                        break;
                    case PSA_IPC_DISCONNECT:
                        puts("Got a disconnection message");
                        ret = PSA_SUCCESS;
                        break;

                    default:
                        printf("Got an IPC call of type %d\n", msg.type);
                        ret = 42;
                        size_t size = msg.in_size[0];

                        if ((size > 0) && (size <= sizeof(foo))) {
                            psa_read(msg.handle, 0, foo, 6);
                            foo[(BUF_SIZE-1)] = '\0';
                            printf("Reading payload: %s\n", foo);
                            psa_read(msg.handle, 0, foo+6, 6);
                            foo[(BUF_SIZE-1)] = '\0';
                            printf("Reading payload: %s\n", foo);
                        }

                        size = msg.out_size[0];
                        if ((size > 0)) {
                            puts("Writing response");
                            psa_write(msg.handle, 0, "RESP", 4);
                            psa_write(msg.handle, 0, "ONSE", 4);
                        }

                        if (msg.client_id > 0) {
                            psa_notify(msg.client_id);
                        } else {
                            puts("Client is non-secure, so won't notify");
                        }

                }

                psa_reply(msg.handle, ret);
            } else {
                puts("Failed to retrieve message");
            }
        } else if (SIGSTP_SIG & signals) {
            puts("Recieved SIGSTP signal. Gonna EOI it.");
            psa_eoi(SIGSTP_SIG);
        } else if (SIGINT_SIG & signals) {
            puts("Handling interrupt!\n");
            puts("Gracefully quitting");
            psa_panic();
        } else {
            puts("No signal asserted");
        }
    }
}
