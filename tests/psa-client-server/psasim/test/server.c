/* psasim test server */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <unistd.h>
#include <stdio.h>

#include "psa/service.h"
#include "psa/error.h"
#include "psa/util.h"
#include "psa_manifest/manifest.h"

#define SERVER_PRINT(fmt, ...) \
    PRINT("Server: " fmt, ##__VA_ARGS__)

#define BUF_SIZE 25

static int kill_on_disconnect = 0; /* Kill the server on client disconnection. */

void parse_input_args(int argc, char *argv[])
{
    int opt;

    while ((opt = getopt(argc, argv, "k")) != -1) {
        switch (opt) {
            case 'k':
                kill_on_disconnect = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-k]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
}

int psa_sha256_main(int argc, char *argv[])
{
    psa_status_t ret = PSA_ERROR_PROGRAMMER_ERROR;
    psa_msg_t msg = { -1 };
    char foo[BUF_SIZE] = { 0 };
    const int magic_num = 66;
    int client_disconnected = 0;

    parse_input_args(argc, argv);
    SERVER_PRINT("Starting");

    while (!(kill_on_disconnect && client_disconnected)) {
        psa_signal_t signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

        if (signals > 0) {
            SERVER_PRINT("Signals: 0x%08x", signals);
        }

        if (signals & PSA_SHA256_SIGNAL) {
            if (PSA_SUCCESS == psa_get(PSA_SHA256_SIGNAL, &msg)) {
                SERVER_PRINT("My handle is %d", msg.handle);
                SERVER_PRINT("My rhandle is %p", (int *) msg.rhandle);
                switch (msg.type) {
                    case PSA_IPC_CONNECT:
                        SERVER_PRINT("Got a connection message");
                        psa_set_rhandle(msg.handle, (void *) &magic_num);
                        ret = PSA_SUCCESS;
                        break;
                    case PSA_IPC_DISCONNECT:
                        SERVER_PRINT("Got a disconnection message");
                        ret = PSA_SUCCESS;
                        client_disconnected = 1;
                        break;

                    default:
                        SERVER_PRINT("Got an IPC call of type %d", msg.type);
                        ret = 42;
                        size_t size = msg.in_size[0];

                        if ((size > 0) && (size <= sizeof(foo))) {
                            psa_read(msg.handle, 0, foo, 6);
                            foo[(BUF_SIZE-1)] = '\0';
                            SERVER_PRINT("Reading payload: %s", foo);
                            psa_read(msg.handle, 0, foo+6, 6);
                            foo[(BUF_SIZE-1)] = '\0';
                            SERVER_PRINT("Reading payload: %s", foo);
                        }

                        size = msg.out_size[0];
                        if ((size > 0)) {
                            SERVER_PRINT("Writing response");
                            psa_write(msg.handle, 0, "RESP", 4);
                            psa_write(msg.handle, 0, "ONSE", 4);
                        }

                        if (msg.client_id > 0) {
                            psa_notify(msg.client_id);
                        } else {
                            SERVER_PRINT("Client is non-secure, so won't notify");
                        }

                }

                psa_reply(msg.handle, ret);
            } else {
                SERVER_PRINT("Failed to retrieve message");
            }
        } else if (SIGSTP_SIG & signals) {
            SERVER_PRINT("Recieved SIGSTP signal. Gonna EOI it.");
            psa_eoi(SIGSTP_SIG);
        } else if (SIGINT_SIG & signals) {
            SERVER_PRINT("Handling interrupt!");
            SERVER_PRINT("Gracefully quitting");
            psa_panic();
        } else {
            SERVER_PRINT("No signal asserted");
        }
    }

    return 0;
}
