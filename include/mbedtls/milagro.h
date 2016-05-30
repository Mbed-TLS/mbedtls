
/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

/*
 * milagro.h
 * 
 * support for milagro_p2p and milagro_cs
 * require an extern library: milagro-crypto
 *
 */



#ifndef milagro_h
#define milagro_h

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <time.h>
#define mbedtls_printf printf
#define mbedtls_calloc calloc
#define mbedtls_free   free
#define mbedtls_time    time
#define mbedtls_time_t  time_t
#endif

#include "mpin.h"
#include "utils.h"
#include "wcc.h"

#include "mbedtls/entropy.h"

#define MILAGRO_CS_TV_DIFFERENCE             5   /* maximum difference of time_values permitted */
#define hashDoneOFF                          0   /* parameter needed by Milagro_p2p */
#define hashDoneON                           1   /* parameter needed by Milagro_p2p */

#define MBEDTLS_MILAGRO_IS_CLIENT                   0
#define MBEDTLS_MILAGRO_IS_SERVER                   1

/*
 * Definition functions from milagro-crypto library
 */
#define mbedtls_milagro_cs_today MPIN_today 
#define mbedtls_milagro_cs_create_csprng MPIN_CREATE_CSPRNG
#define mbedtls_milagro_cs_hash_id MPIN_HASH_ID
#define mbedtls_milagro_cs_get_time MPIN_GET_TIME
#define mbedtls_milagro_cs_client MPIN_CLIENT
#define mbedtls_milagro_cs_server MPIN_SERVER
#define mbedtls_milagro_cs_get_g1_multiple MPIN_GET_G1_MULTIPLE
#define mbedtls_milagro_cs_kill_csprng MPIN_KILL_CSPRNG
#define mbedtls_milagro_cs_hash_all MPIN_HASH_ALL
#define mbedtls_milagro_cs_server_key MPIN_SERVER_KEY
#define mbedtls_milagro_cs_precompute MPIN_PRECOMPUTE
#define mbedtls_milagro_cs_client_key MPIN_CLIENT_KEY
#define mbedtls_milagro_p2p_create_csprng WCC_CREATE_CSPRNG
#define mbedtls_milagro_p2p_random_generate WCC_RANDOM_GENERATE
#define mbedtls_milagro_p2p_get_g1_multiple WCC_GET_G1_MULTIPLE
#define mbedtls_milagro_p2p_get_g2_multiple WCC_GET_G2_MULTIPLE
#define mbedtls_milagro_p2p_kill_csprng WCC_KILL_CSPRNG
#define mbedtls_milagro_p2p_hq WCC_Hq
#define mbedtls_milagro_p2p_sender_key WCC_SENDER_KEY
#define mbedtls_milagro_p2p_receiver_key WCC_RECEIVER_KEY


/*
 * MILAGRO_CS errors
 */
#define MBEDTLS_ERR_MILAGRO_CS_AUTHENTICATION_FAILED    -0x6680  /**< The server has failed authenticating the client. */
#define MBEDTLS_ERR_MILAGRO_CS_SRV_PUB_PARAM_FAILED     -0x6600  /**< The server has failed computing the public parameter. */
#define MBEDTLS_ERR_MILAGRO_CS_CLI_PUB_PARAM_FAILED     -0x6580  /**< The client has failed computing the public parameter. */
#define MBEDTLS_ERR_MILAGRO_CS_READ_PARAM_FAILED        -0x6560  /**< The client/server has failed reading a public parameter. */
#define MBEDTLS_ERR_MILAGRO_CS_WRITE_PARAM_FAILED       -0x6540  /**< Failed while writing the parameters. */
#define MBEDTLS_ERR_MILAGRO_CS_KEY_COMPUTATOIN_FAILED   -0x6500  /**< The client/server has failed computing the premaster key. */
/*
 * MILAGRO_P2P errors
 */
#define MBEDTLS_ERR_MILAGRO_P2P_READ_PARAM_FAILED               -0x6480
#define MBEDTLS_ERR_MILAGRO_P2P_PARAMETERS_COMPUTATOIN_FAILED   -0x6400  /**< The client/server has failed computing the parameters. */
#define MBEDTLS_ERR_MILAGRO_P2P_MSECRET_COMPUTATOIN_FAILED      -0x6380  /**< The client/server has failed computing the premaster secret. */
#define MBEDTLS_ERR_MILAGRO_P2P_WRITE_PARAM_FAILED              -0x6360  /**< Failed while writing the parameters. */

/*
 * General milagro errors
 */
#define MBEDTLS_ERR_MILAGRO_BAD_INPUT       -0x6340  /**< Input function non valid. */


/* defined below */
typedef struct mbedtls_milagro_cs_context mbedtls_milagro_cs_context;
typedef struct mbedtls_milagro_p2p_context mbedtls_milagro_p2p_context;



/**
 * \brief           Allocating function used internally in milagro.c
 *
 * \param nbytes    number of bytes to allocate
 */
void* mbedtls_milagro_calloc(size_t nbytes);

/**
 * \brief                Freeing function used internally in milagro.c
 *
 * \param to_be_freed    octet to be freed
 */
void mbedtls_milagro_free_octet(octet *to_be_freed);

// Milagro Client-to-Server

/**
 * \brief           Struct inside handshake for MILAGRO_CS
 *
 * \note            the octet struct is defined in the
 *                  milagro-crypto library
 */
struct mbedtls_milagro_cs_context
{
    /*
     * See the paper M-Pin: A Multi-Factor Zero Knowledge Authentication
     * Protocol by Michael Scott for the notation
     */
#if defined(MBEDTLS_SSL_CLI_C)
    octet X;                  /*!< Random number internally generated by the client                   */
    octet G1;                 /*!< Parameter for the computation of the key                           */
    octet G2;                 /*!< Parameter for the computation of the key                           */
    octet time_permits;       /*!< Time Permits in case is required, otherwise is NULL                */
    int pin;                  /*!< 4 digit pin, is 0 if not required                                  */
#endif
#if defined(MBEDTLS_SSL_SRV_C)
    octet HID;                 /*!< Parameter owned only by the server (case no time permits)         */
    octet HTID;                /*!< Parameter owned only by the server (case with time permits)       */
#endif
    octet param_rand;         /*!< Random number internally generated by the server and client        */
    octet W;                  /*!< Public parameter sent to the client for the key computation        */
    octet R;                  /*!< Public parameter sent to the server for the key computation        */
    octet secret;             /*!< Secret provided by the TA (different for client and server)
                                    in case of required PIN, is the token                             */
    octet U;                  /*!< It is the output x.H(ID), in case of time permit has
                                    to be set to NULL                                                 */
    octet UT;                 /*!< It is the output x.(H(ID)+H(d|H(ID))) in case of Time Permit       */
    octet client_identity;    /*!< Client's identity                                                  */
    octet hash_client_id;     /*!< Hash of the client's identity                                      */
    octet Y;                  /*!< Parameter computed from both sides                                 */
    octet V;                  /*!< Output point on EC computed by the client for the authentication   */
    octet H;                  /*!< Hash of some parameters computed at both sides                     */
    octet Key;                /*!< Key generated at the end of the MILAGRO_CS protocol                */
    csprng RNG;               /*!< Random Number Generator                                            */
    int date;                 /*!< date to use in case of Time Permits, otherwise is set to 0         */
    unsign32 timevalue;       /*!< time value to use in case of Time Permits, otherwise is set to 0   */
};


/**
 * \brief           Initialize an milagro_cs struct
 *
 * \param milagro_cs          milagro_cs to be initialized
 *
 */
void mbedtls_milagro_cs_init( struct mbedtls_milagro_cs_context * milagro_cs);


/**
 * \brief           Set up the random number generator for the milagro_cs struct
 *
 * \note            the seed came from this library, the random generator
 *                  from the milagro-crypto library
 *
 * \param milagro_cs      milagro_cs struct which contains the parameter RNG to be
 *                  set up
 * \param entropy       entropy already initialized
 *
 */
int mbedtls_milagro_cs_setup_RNG( mbedtls_milagro_cs_context *milagro_cs, mbedtls_entropy_context *entropy);


/**
 * \brief           Set up the secret provided by the DTAs
 *
 * \param milagro_cs      milagro_cs struct which contains the parameters
 *                        to be initialized
 * \param secret          secret to store
 * \param len_secret      length of the secret
 *
 */
void mbedtls_milagro_cs_set_secret( mbedtls_milagro_cs_context *milagro_cs, char* secret, int len_secret);

#if defined(MBEDTLS_SSL_CLI_C)
/**
 * \brief           Set up the secret provided by the DTAs
 *
 * \param milagro_cs      milagro_cs struct which contains the parameters
 *                        to be initialized
 * \param client_identity       the identity of the client
 *
 */
void mbedtls_milagro_cs_set_client_identity(mbedtls_milagro_cs_context *milagro_cs, char * client_identity);
#endif

/**
 * \brief           Set up the parameters used by the milagro_cs
 *
 * \param milagro_cs      milagro_cs struct which contains the parameters
 *                        to be initialized
 * \param timepermit          time permit for the client
 * \param len_timepermit      length of time permit
 *
 */
void mbedtls_milagro_cs_set_timepermit( mbedtls_milagro_cs_context *milagro_cs, char* timepermit, int len_timepermit);


/**
 * \brief          Alloc memory for the parameters used by the milagro_cs, inc
 *                 case of the client it computes also the public parameters to
 *                 be sent with the clientHello
 *
 * \param client_or_server 1 if server, 0 if client
 * \param milagro_cs      milagro_cs struct which contains the parameters
 *                  to be initialized
 *
 */
int mbedtls_milagro_cs_alloc_memory(int client_or_server, mbedtls_milagro_cs_context *milagro_cs);

/**
 * \brief           Check if the server's parameters are ok
 *
 *
 * \param client_or_server      0 if client, 1 if server
 * \param milagro_cs      milagro_cs struct which contains the parameters
 *                  to be initialized
 *
 * \retun           0 if the parameters are good, -1 otherwise
 *
 */
int mbedtls_milagro_cs_check(int client_or_server, mbedtls_milagro_cs_context *milagro_cs );

#if defined(MBEDTLS_SSL_SRV_C)
/**
 * \brief           read the parameters sent by the client
 *
 *
 * \param milagro_cs      milagro_cs struct in which the parameters has to be
 *                        stored
 * \param buf             buffer where to copy the parameters
 * \param len             length of the extension
 *
 */
int mbedtls_milagro_cs_read_client_parameters( mbedtls_milagro_cs_context *milagro_cs, const unsigned char *buf, size_t len );

/**
 * \brief           read the parameters sent by the client
 *
 *
 * \param milagro_cs      milagro_cs struct in which the parameters has to be
 *                  stored
 *
 * \retun           0 if the reading finish well, -1 otherwise
 *
 */
int mbedtls_milagro_cs_authenticate_client( mbedtls_milagro_cs_context *milagro_cs );

#endif

/**
 * \brief           Generate and write the public parameter in order to
 *                  compute the key (TLS: contents of the Client/ServerKeyExchange)
 *
 * \param client_or_server      0 if client, 1 if server
 * \param milagro_cs            Context to use
 * \param buf                   Buffer to write the contents to
 * \param len                   Buffer size
 * \param ec_point_len          Will be updated with the number of bytes written
 *
 * \return                      0 if successful, a negative error code otherwise
 *
 */
int mbedtls_milagro_cs_write_exchange_parameter( int client_or_server, mbedtls_milagro_cs_context *milagro_cs,
                                          unsigned char *buf, size_t len, size_t *ec_point_len );


/**
 * \brief           Read the public parameter for the computation of the Key
 *                  (TLS: contents of the Client/ServerKeyExchange)
 *
 * \param client_or_server      0 if client, 1 if server
 * \param milagro_cs            Context to use
 * \param buf                   Pointer to the message
 * \param len                   Message length
 *
 * \return                      0 if successful, a negative error code otherwise
 *
 */
int mbedtls_milagro_cs_read_public_parameter( int client_or_server, mbedtls_milagro_cs_context *milagro_cs,

                                             const unsigned char *buf, size_t len  );
/**
 * \brief           Compute the shared secret at client's side
 *
 * \param milagro_cs            Context to use
 *
 * \return                      0 if successful, a negative error code otherwise
 *
 */
int mbedtls_milagro_cs_share_secret_cli(mbedtls_milagro_cs_context *milagro_cs);


/**
 * \brief           Compute the shared secret at server's side
 *
 * \param milagro_cs            Context to use
 *
 * \return                      0 if successful, a negative error code otherwise
 *
 */
int mbedtls_milagro_cs_share_secret_srv(mbedtls_milagro_cs_context *milagro_cs);


/**
 * \brief           Free the context milagro_cs
 *
 * \param milagro_cs      milagro_cs context to be freed
 *
 */
void mbedtls_milagro_cs_free( mbedtls_milagro_cs_context *milagro_cs);



// Milagro Peer-to-Peer

// peer1 is the server
// peer2 is the client


/**
 * \brief           struct inside the handshake for MILAGRO_P2P
 *
 * \note            the octet struct is defined in the
 *                  milagro-crypto library
 */
struct mbedtls_milagro_p2p_context
{
    /*
     * See the paper TODO what paper?
     *
     */
    int date;                  /*!< set to zero in case of not using time permit                      */
    octet client_rec_key;      /*!< Client's receiver key provided by the TA                          */
    octet server_sen_key;      /*!< Server's sender key provided by the TA                            */
    octet X;                   /*!< Random number internally generated by the server                  */
    octet W;                   /*!< Random number internally generated by the client                  */
    octet Y;                   /*!< Random number internally generated by the client                  */
    octet server_identity;     /*!< Client Identity                                                   */
    octet client_identity;     /*!< Server Identity                                                   */
    octet server_pub_param_G1; /*!< Server's public parameter in the group G1                         */
    octet client_pub_param_G1; /*!< Client's public parameter in the group G1                         */
    octet client_pub_param_G2; /*!< Client's public parameter in the group G2                         */
    octet client_PIA;          /*!< Client's private parameter                                        */
    octet client_PIB;          /*!< Client's private parameter                                        */
    octet shared_secret;       /*!< Shared secret computed by at the two sides                        */
    csprng RNG;                /*!< Random Number Generator                                           */
};



/**
 * \brief                  Initialize an milagro_p2p struct
 *
 * \param milagro_p2p      milagro_cs to be initialized
 *
 */
void mbedtls_milagro_p2p_init( mbedtls_milagro_p2p_context * milagro_p2p);


/**
 * \brief                 Set up the receiver/sender key provided by the DTAs
 *
 * \param milagro_p2p     milagro_p2p struct which contains the parameters
 *                        to be initialized
 * \param key             sender/receiver key to store
 * \param len_key         length of the key
 *
 */
void mbedtls_milagro_p2p_set_key(int client_or_server, mbedtls_milagro_p2p_context *milagro_p2p, char* key, int len_key);


/**
 * \brief                 Make the first server's side computation
 *
 * \param milagro_p2p     milagro_p2p struct which contains the parameters
 *
 * \return                0 if successful, error otherwise
 */
int mbedtls_milagro_p2p_compute_public_param( mbedtls_milagro_p2p_context *milagro_p2p);


/**
 * \brief                Set up the random number generator for the milagro_p2p struct
 *
 * \note                 the seed came from this library, the random generator
 *                       from the milagro-crypto library
 *
 * \param milagro_p2p    milagro_cs struct which contains the parameter RNG to be
 *                       set up
 * \param entropy        entropy already initialized
 *
 */
int mbedtls_milagro_p2p_setup_RNG( mbedtls_milagro_p2p_context *milagro_p2p, mbedtls_entropy_context *entropy);


/**
 * \brief                     Allocate memory and store the identity
 *
 * \param client_or_server    1 if server, 0 if client
 * \param milagro_p2p         milagro_p2p struct which contains the parameter
 * \param identity            identity to be stored
 *
 * \return                    0 if successful, error otherwise
 */
int mbedtls_milagro_p2p_set_identity(int client_or_server, mbedtls_milagro_p2p_context *milagro_p2p, char * identity);


/**
 * \brief                     Alloc memory for the struct milagro_p2p
 *
 * \param client_or_server    1 if server, 0 if client
 * \param milagro_p2p         milagro_p2p struct which contains the parameters
 *                            to be initialized
 *
 * \return                    0 if successful, error otherwise
 */int mbedtls_milagro_p2p_alloc_memory(int client_or_server, mbedtls_milagro_p2p_context *milagro_p2p);


/**
 * \brief                       Generate and write the public parameter (ServerKeyExchange)
 *
 * \param client_or_server      0 if client, 1 if server
 * \param milagro_p2p           Context to use
 * \param buf                   Buffer to write the contents to
 * \param len                   Buffer size
 * \param param_len             Will be updated with the number of bytes written
 *
 * \return                      0 if successful,
 *                              a negative error code otherwise
 */
int mbedtls_milagro_p2p_write_public_parameters(int client_or_server, mbedtls_milagro_p2p_context *milagro_p2p,
                                                unsigned char *buf, size_t len, size_t *param_len );


/**
 * \brief                       Read the public parameter (KeyExchange)
 *
 * \param client_or_server      0 if client, 1 if server
 * \param milagro_p2p           Context to use
 * \param buf                   Pointer to the message
 * \param len                   Message length
 *
 * \return                      0 if successful,
 *                              a negative error code otherwise
 */
int mbedtls_milagro_p2p_read_public_parameters( int client_or_server, mbedtls_milagro_p2p_context *milagro_p2p,
                                             const unsigned char *buf, size_t len  );

/**
 * \brief           Compute the shared secret at client's side
 *
 * \param milagro_cs            Context to use
 *
 * \return                      0 if successful, a negative error code otherwise
 *
 */
int mbedtls_milagro_p2p_share_secret_cli(mbedtls_milagro_p2p_context *milagro_p2p);


/**
 * \brief           Compute the shared secret at server's side
 *
 * \param milagro_cs            Context to use
 *
 * \return                      0 if successful, a negative error code otherwise
 *
 */
int mbedtls_milagro_p2p_share_secret_srv(mbedtls_milagro_p2p_context *milagro_p2p);


/**
 * \brief           Free the context milagro_p2p
 *
 * \param milagro_p2p      milagro_p2p context to be freed
 *
 */
void mbedtls_milagro_p2p_free( mbedtls_milagro_p2p_context *milagro_p2p);


#endif /* milagro_h */






