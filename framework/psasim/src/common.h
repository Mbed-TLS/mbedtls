/* Common definitions used for clients and services */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <psa/service.h>

#ifdef DEBUG
#define DEBUG_TEST 1
#else
#define DEBUG_TEST 0
#endif

#define PRINT(...) \
    do { if (DEBUG_TEST) fprintf(stderr, __VA_ARGS__); } while (0)
#define INFO(...) \
    do { if (DEBUG_TEST) { PRINT("%s", __FILE__); PRINT(" INFO: " __VA_ARGS__); printf("\n"); \
         } } while (0)

#define PROGRAMMER_ERROR(...) \
    do { if (DEBUG_TEST) { PRINT("%s:%d:%s(): PROGRAMMER ERROR", __FILE__, __LINE__, __func__); \
                           PRINT(__VA_ARGS__); } abort(); } while (0)

#define FATAL(...) \
    do { if (DEBUG_TEST) { PRINT("%s:%d:%s(): INTERNAL ERROR", __FILE__, __LINE__, __func__); PRINT( \
                               __VA_ARGS__); } abort(); } while (0)


#define PROJECT_ID 'M'
#define PATHNAMESIZE 64

/* Increasing this might break on some platforms */
#define MAX_FRAGMENT_SIZE 200

#define CONNECT_REQUEST 1
#define CALL_REQUEST 2
#define CLOSE_REQUEST 3
#define VERSION_REQUEST 4
#define READ_REQUEST    5
#define READ_RESPONSE   6
#define WRITE_REQUEST   7
#define WRITE_RESPONSE  8
#define SKIP_REQUEST    9
#define PSA_REPLY       10

#define NON_SECURE (1 << 30)

/* Note that this implementation is functional and not secure */
extern int __psa_ff_client_security_state;

struct message_text {
    int qid;
    int32_t psa_type;
    char buf[MAX_FRAGMENT_SIZE];
};


struct message {
    long message_type;
    struct message_text message_text;
};

struct request_msg_internal {
    psa_invec invec;
    size_t skip_num;
};

struct skip_request_msg {
    long message_type;
    struct request_msg_internal message_text;
};

typedef struct vectors {
    const psa_invec *in_vec;
    size_t in_len;
    psa_outvec *out_vec;
    size_t out_len;
} vectors_t;

typedef struct vector_sizes {
    size_t invec_sizes[PSA_MAX_IOVEC];
    size_t outvec_sizes[PSA_MAX_IOVEC];
} vector_sizes_t;
