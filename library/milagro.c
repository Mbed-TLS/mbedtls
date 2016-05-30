
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
 * milagro.c
 *
 * support for milagro_p2p and milagro_cs
 * require an extern library: milagro-crypto
 *
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "mbedtls/milagro.h"

#if defined(MBEDTLS_MILAGRO_CS_C) || defined(MBEDTLS_MILAGRO_P2P_C)

void* mbedtls_milagro_calloc(size_t nbytes)
{
    void *r;
    if(!nbytes)
    {
        fprintf(stderr,"%s() called with zero bytes to alloc\n",__func__);
        exit(EXIT_FAILURE);
    }
    r = mbedtls_calloc(1,nbytes);
    if(!r)
    {
        fprintf(stderr, "%s() failed on allocation on  %lu bytes to alloc\n",__func__, (unsigned long)nbytes);
        exit(EXIT_FAILURE);
    }
    return r;
}

void mbedtls_milagro_free_octet(octet *to_be_freed)
{
    if(to_be_freed && to_be_freed->val)
    {
        mbedtls_free(to_be_freed->val);
        to_be_freed->val = NULL;
        to_be_freed = NULL;
    }
}

#endif /* defined(MBEDTLS_MILAGRO_CS_C) || defined(MBEDTLS_MILAGRO_P2P_C) */

#if defined(MBEDTLS_MILAGRO_CS_C)

void mbedtls_milagro_cs_init( mbedtls_milagro_cs_context * milagro_cs)
{
    memset(milagro_cs,0,sizeof(*milagro_cs));
    
#if defined(MBEDTLS_MILAGRO_CS_TIME_PERMITS)
    milagro_cs->date = mbedtls_milagro_cs_today();
#endif
}


int mbedtls_milagro_cs_setup_RNG( mbedtls_milagro_cs_context *milagro_cs, mbedtls_entropy_context *entropy)
{
    unsigned char seed[20] = {0};
    char raw[100] = {0};
    
    octet RAW={0,sizeof(raw),raw};
    
    for (int i = 0; i<5; i++) {
        if (mbedtls_entropy_func(entropy, seed, 20) != 0)
        {
            return(MBEDTLS_ERR_ENTROPY_SOURCE_FAILED);
        }
        RAW.len=100;
        memcpy(RAW.val+i*20,&seed,20);
    }
    /* initialise strong RNG */
    mbedtls_milagro_cs_create_csprng(&milagro_cs->RNG,&RAW);
    
    return 0;
}

void mbedtls_milagro_cs_set_timepermit(mbedtls_milagro_cs_context *milagro_cs, char* timepermit, int len_timepermit)
{
    milagro_cs->time_permits.val = mbedtls_milagro_calloc(256);
    memcpy(milagro_cs->time_permits.val, timepermit, len_timepermit);
    milagro_cs->time_permits.max = len_timepermit;
}



void mbedtls_milagro_cs_set_client_identity(mbedtls_milagro_cs_context *milagro_cs, char * client_identity)
{
    milagro_cs->client_identity.val = mbedtls_milagro_calloc((int)strlen(client_identity)+1);
    milagro_cs->hash_client_id.val = mbedtls_milagro_calloc(PGS);
    milagro_cs->hash_client_id.max = PGS;
    milagro_cs->hash_client_id.len = PGS;
    memcpy(milagro_cs->client_identity.val, client_identity, strlen(client_identity));
    milagro_cs->client_identity.len = (int)strlen(client_identity);
    milagro_cs->client_identity.max = (int)strlen(client_identity);
    mbedtls_milagro_cs_hash_id(&milagro_cs->client_identity,&milagro_cs->hash_client_id);
}
    
void mbedtls_milagro_cs_set_secret(mbedtls_milagro_cs_context *milagro_cs, char* secret, int len_secret)
{
    milagro_cs->secret.val = mbedtls_milagro_calloc(256);
    memcpy(milagro_cs->secret.val, secret, len_secret);
    milagro_cs->secret.len = len_secret;
}


        
int mbedtls_milagro_cs_alloc_memory(int client_or_server, mbedtls_milagro_cs_context *milagro_cs)
{
    // Set memory of parameters to be fit
    milagro_cs->Y.val = mbedtls_milagro_calloc(PGS);
    milagro_cs->V.val = mbedtls_milagro_calloc(2*PFS+1);
    milagro_cs->UT.val = mbedtls_milagro_calloc(2*PFS+1);
    milagro_cs->U.val = mbedtls_milagro_calloc(2*PFS+1);
    milagro_cs->W.val = mbedtls_milagro_calloc(2*PFS+1);
    milagro_cs->R.val = mbedtls_milagro_calloc(2*PFS+1);
    milagro_cs->param_rand.val = mbedtls_milagro_calloc(PGS);
    milagro_cs->H.val = mbedtls_milagro_calloc(PGS);
    milagro_cs->H.max = PGS;
    milagro_cs->Key.val = mbedtls_milagro_calloc(PAS);
    milagro_cs->Key.max = PAS;
    milagro_cs->timevalue = mbedtls_milagro_cs_get_time();
    
    if(client_or_server == MBEDTLS_MILAGRO_IS_SERVER)
    {
        milagro_cs->HID.val = mbedtls_milagro_calloc(2*PFS+1);
        milagro_cs->HID.len = 2*PFS+1;
        milagro_cs->HTID.val = mbedtls_milagro_calloc(2*PFS+1);
        milagro_cs->HTID.len = 2*PFS+1;
    }
    else if(client_or_server == MBEDTLS_MILAGRO_IS_CLIENT)
    {
        milagro_cs->X.val = mbedtls_milagro_calloc(PGS);

        if (mbedtls_milagro_cs_client(milagro_cs->date,
                                      &milagro_cs->client_identity,
                                      &milagro_cs->RNG,
                                      &milagro_cs->X,
                                      milagro_cs->pin,
                                      &milagro_cs->secret,
                                      &milagro_cs->V,
                                      &milagro_cs->U,
                                      &milagro_cs->UT,
                                      &milagro_cs->time_permits, NULL,
                                      milagro_cs->timevalue,
                                      &milagro_cs->Y) != 0)
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }
    return 0;
}

int mbedtls_milagro_cs_check(int client_or_server, mbedtls_milagro_cs_context *milagro_cs )
{
    
    if (!(milagro_cs->secret.val &&
        &milagro_cs->RNG.pool[0] &&
        &milagro_cs->RNG.ira[0]))
    {
        return -1;
    }

#if defined(MBEDTLS_MILAGRO_CS_TIME_PERMITS)
    if(client_or_server == MBEDTLS_MILAGRO_IS_CLIENT && milagro_cs->time_permits.val == NULL)
    {
        return -1;
    }
#endif
    return 0;
}

#if defined(MBEDTLS_SSL_SRV_C)

int mbedtls_milagro_cs_read_client_parameters( mbedtls_milagro_cs_context *milagro_cs, const unsigned char *buf, size_t len )
{
    unsign32 client_time = 0;
    int32_t check_time = 0;
    // Copy the client's identity length
    milagro_cs->hash_client_id.len = UINT16_MAX & (buf[1] |((uint16_t)buf[0])<< 8);
    milagro_cs->hash_client_id.val = mbedtls_milagro_calloc(milagro_cs->hash_client_id.len);

#if defined(MBEDTLS_MILAGRO_CS_TIME_PERMITS)
    // Copy the length of the parameter UT
    milagro_cs->UT.len =  UINT16_MAX & (buf[3] |((uint16_t)buf[2])<< 8);
#else
    // Copy the length of the parameter UT
    milagro_cs->U.len =  UINT16_MAX & (buf[3] |((uint16_t)buf[2])<< 8);
#endif
    // Copy the length of the parameter V
    milagro_cs->V.len = UINT16_MAX & (buf[5] |((uint16_t)buf[4])<< 8);
    
    // Copy the client identity
    memcpy(milagro_cs->hash_client_id.val, &buf[6], milagro_cs->hash_client_id.len);
#if defined(MBEDTLS_MILAGRO_CS_TIME_PERMITS)
    // Copy the parameter UT
    memcpy(milagro_cs->UT.val, &buf[6+milagro_cs->hash_client_id.len], milagro_cs->UT.len);
    // Copy the parameter V
    memcpy(milagro_cs->V.val, &buf[6+milagro_cs->hash_client_id.len+milagro_cs->UT.len], milagro_cs->V.len);
    // Copy the timevalue
    client_time |= (UINT32_MAX & (buf[6+milagro_cs->hash_client_id.len+milagro_cs->UT.len+
                                      milagro_cs->V.len  ] << 24 ));
    client_time |= (UINT32_MAX & (buf[6+milagro_cs->hash_client_id.len+milagro_cs->UT.len+
                                      milagro_cs->V.len+1] << 16));
    client_time |= (UINT32_MAX & (buf[6+milagro_cs->hash_client_id.len+milagro_cs->UT.len+
                                      milagro_cs->V.len+2] <<  8));
    client_time |= (UINT32_MAX & (buf[6+milagro_cs->hash_client_id.len+milagro_cs->UT.len+
                                      milagro_cs->V.len+3 ]      ));

#else
    // Copy the parameter U
    memcpy(milagro_cs->U.val, &buf[6+milagro_cs->hash_client_id.len], milagro_cs->U.len);
    // Copy the parameter V
    memcpy(milagro_cs->V.val, &buf[6+milagro_cs->hash_client_id.len+milagro_cs->U.len], milagro_cs->V.len);
    // Copy the timevalue
    client_time |= (UINT32_MAX & (buf[6+milagro_cs->hash_client_id.len+milagro_cs->U.len+
                                      milagro_cs->V.len  ] << 24 ));
    client_time |= (UINT32_MAX & (buf[6+milagro_cs->hash_client_id.len+milagro_cs->U.len+
                                      milagro_cs->V.len+1] << 16));
    client_time |= (UINT32_MAX & (buf[6+milagro_cs->hash_client_id.len+milagro_cs->U.len+
                                      milagro_cs->V.len+2] <<  8));
    client_time |= (UINT32_MAX & (buf[6+milagro_cs->hash_client_id.len+milagro_cs->U.len+
                                      milagro_cs->V.len+3 ]      ));
#endif
    check_time = client_time-milagro_cs->timevalue;
    
    if(abs(check_time)<=MILAGRO_CS_TV_DIFFERENCE)
        milagro_cs->timevalue = client_time;
    else
        return(MBEDTLS_ERR_MILAGRO_CS_AUTHENTICATION_FAILED);
    
    if((int)len != milagro_cs->hash_client_id.len +
#if defined(MBEDTLS_MILAGRO_CS_TIME_PERMITS)
       milagro_cs->UT.len +
#else
       milagro_cs->U.len +
#endif
       milagro_cs->V.len + 10)
        return(MBEDTLS_ERR_MILAGRO_CS_AUTHENTICATION_FAILED);
    
    return 0;
}


int mbedtls_milagro_cs_authenticate_client( mbedtls_milagro_cs_context *milagro_cs )
{
    int ret = 0;
    if ( mbedtls_milagro_cs_server(milagro_cs->date,&milagro_cs->HID,&milagro_cs->HTID,&milagro_cs->Y,&milagro_cs->secret,&milagro_cs->U,
                     &milagro_cs->UT,&milagro_cs->V,NULL,NULL,&milagro_cs->hash_client_id,NULL,milagro_cs->timevalue) != 0)
    {
        ret = MBEDTLS_ERR_MILAGRO_CS_AUTHENTICATION_FAILED;
    }
    
    return ret;
}


#endif /* MBEDTLS_SSL_SRV_C */

int mbedtls_milagro_cs_write_exchange_parameter( int client_or_server, mbedtls_milagro_cs_context *milagro_cs,
                                          unsigned char *buf, size_t len, size_t *ec_point_len )
{
    unsigned char *p = buf;
    const unsigned char *end = buf + len;
    
    if(client_or_server == MBEDTLS_MILAGRO_IS_CLIENT)
    {
        if(mbedtls_milagro_cs_get_g1_multiple(&milagro_cs->RNG,1,&milagro_cs->param_rand,
                                                   &milagro_cs->hash_client_id,&milagro_cs->R) != 0)
        {
            return MBEDTLS_ERR_MILAGRO_CS_CLI_PUB_PARAM_FAILED;
        }
        *p++ = (unsigned char)( ( ( milagro_cs->R.len     ) >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( ( milagro_cs->R.len     )      ) & 0xFF );
        
        memcpy(p, milagro_cs->R.val, milagro_cs->R.len);
        p += milagro_cs->R.len;
    }
    else if(client_or_server == MBEDTLS_MILAGRO_IS_SERVER)
    {
        int ret;
#if defined(MBEDTLS_MILAGRO_CS_TIME_PERMITS)
        ret = mbedtls_milagro_cs_get_g1_multiple(&milagro_cs->RNG,0,&milagro_cs->param_rand,&milagro_cs->HTID,&milagro_cs->W);
#else
        ret = mbedtls_milagro_cs_get_g1_multiple(&milagro_cs->RNG,0,&milagro_cs->param_rand,&milagro_cs->HID,&milagro_cs->W);
#endif
        if( ret != 0)
        {
            return(MBEDTLS_ERR_MILAGRO_CS_SRV_PUB_PARAM_FAILED);
        }
        *p++ = (unsigned char)( ( ( milagro_cs->W.len     ) >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( ( milagro_cs->W.len     )      ) & 0xFF );
        
        memcpy(p, milagro_cs->W.val, milagro_cs->W.len);
        p += milagro_cs->W.len;
    }
    else
    {
        return(MBEDTLS_ERR_MILAGRO_BAD_INPUT);
    }
    
    if( end < p )
    {
        return(MBEDTLS_ERR_MILAGRO_CS_CLI_PUB_PARAM_FAILED);
    }
    
    *ec_point_len = p - buf;
    return 0;
}

int mbedtls_milagro_cs_read_public_parameter( int client_or_server, mbedtls_milagro_cs_context *milagro_cs,
                                       const unsigned char *buf, size_t len  )
{
#if defined(MBEDTLS_SSL_CLI_C)
    if(client_or_server == MBEDTLS_MILAGRO_IS_CLIENT)
    {
        // Copy the length of the parameter W
        milagro_cs->W.len =  UINT16_MAX & (buf[1] |((uint16_t)buf[0])<< 8);
        
        // Copy the parameter W
        memcpy(milagro_cs->W.val, &buf[2], milagro_cs->W.len);
        if ((int)len != milagro_cs->W.len + 2)
        {
            return (MBEDTLS_ERR_MILAGRO_CS_READ_PARAM_FAILED);
        }
    }
    else
#endif
#if defined(MBEDTLS_SSL_SRV_C)
    if(client_or_server == MBEDTLS_MILAGRO_IS_SERVER)
    {
        // Copy the length of the parameter R
        milagro_cs->R.len =  UINT16_MAX & (buf[1] |((uint16_t)buf[0])<< 8);
        
        // Copy the parameter R
        memcpy(milagro_cs->R.val, &buf[2], milagro_cs->R.len);
        if ((int)len != milagro_cs->R.len + 2)
        {
            return (MBEDTLS_ERR_MILAGRO_CS_READ_PARAM_FAILED);
        }
    }
    else
#endif
        return(MBEDTLS_ERR_MILAGRO_BAD_INPUT);
    
    return 0;
}

#if defined(MBEDTLS_SSL_CLI_C)
int mbedtls_milagro_cs_share_secret_cli(mbedtls_milagro_cs_context *milagro_cs)
{
    int ret = 0;
    char g1[12*PFS],g2[12*PFS];
    octet G1={0,sizeof(g1),g1}, G2={0,sizeof(g2),g2};
    
    mbedtls_milagro_cs_hash_all(&milagro_cs->hash_client_id,
                                &milagro_cs->U,
                                &milagro_cs->UT,
                                &milagro_cs->Y,
                                &milagro_cs->V,
                                &milagro_cs->R,
                                &milagro_cs->W,
                                &milagro_cs->H);
    
    if ( (ret = mbedtls_milagro_cs_precompute(&milagro_cs->secret,
                                              &milagro_cs->hash_client_id,
                                              &G1,&G2) ) != 0)
    {
        return (MBEDTLS_ERR_MILAGRO_CS_KEY_COMPUTATOIN_FAILED);
    }
    
    if ( (ret = mbedtls_milagro_cs_client_key(&G1,&G2,milagro_cs->pin,
                                              &milagro_cs->param_rand,
                                              &milagro_cs->X,
                                              &milagro_cs->H,
                                              &milagro_cs->W,
                                              &milagro_cs->Key) ) != 0)
    {
        return (MBEDTLS_ERR_MILAGRO_CS_KEY_COMPUTATOIN_FAILED);
    }

    
    return 0;
}
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_SRV_C)

int mbedtls_milagro_cs_share_secret_srv(mbedtls_milagro_cs_context *milagro_cs)
{
    int ret = 0;
    
    mbedtls_milagro_cs_hash_all(&milagro_cs->hash_client_id,
                                &milagro_cs->U,
                                &milagro_cs->UT,
                                &milagro_cs->Y,
                                &milagro_cs->V,
                                &milagro_cs->R,
                                &milagro_cs->W,
                                &milagro_cs->H);
    
    milagro_cs->R.max = 2*PGS+1;
    milagro_cs->UT.max = 2*PGS+1;
    milagro_cs->param_rand.max = PGS;
    milagro_cs->secret.max = 4*PGS;
    
#if defined(MBEDTLS_MILAGRO_CS_TIME_PERMITS)
    ret = mbedtls_milagro_cs_server_key(&milagro_cs->R,
                                        &milagro_cs->secret,
                                        &milagro_cs->param_rand,
                                        &milagro_cs->H,
                                        &milagro_cs->HID,
                                        NULL,
                                        &milagro_cs->UT,
                                        &milagro_cs->Key);
#else
    ret = mbedtls_milagro_cs_server_key(&milagro_cs->R,
                                        &milagro_cs->secret,
                                        &milagro_cs->param_rand,
                                        &milagro_cs->H,
                                        &milagro_cs->HID,
                                        &milagro_cs->U,
                                        NULL,
                                        &milagro_cs->Key);
#endif
    if ( ret != 0)
    {
        return (MBEDTLS_ERR_MILAGRO_CS_KEY_COMPUTATOIN_FAILED);
    }
    
    return 0;
}

#endif /* #if MBEDTLS_SSL_SRV_C */

void mbedtls_milagro_cs_free( mbedtls_milagro_cs_context *milagro_cs)
{
    if(!milagro_cs)
        return;
    
    mbedtls_milagro_free_octet(&milagro_cs->X);
    mbedtls_milagro_free_octet(&milagro_cs->G1);
    mbedtls_milagro_free_octet(&milagro_cs->G2);
    mbedtls_milagro_free_octet(&milagro_cs->time_permits);
    mbedtls_milagro_free_octet(&milagro_cs->HID);
    mbedtls_milagro_free_octet(&milagro_cs->HTID);
    mbedtls_milagro_free_octet(&milagro_cs->param_rand);
    mbedtls_milagro_free_octet(&milagro_cs->W);
    mbedtls_milagro_free_octet(&milagro_cs->R);
    mbedtls_milagro_free_octet(&milagro_cs->U);
    mbedtls_milagro_free_octet(&milagro_cs->UT);
    mbedtls_milagro_free_octet(&milagro_cs->hash_client_id);
    mbedtls_milagro_free_octet(&milagro_cs->Y);
    mbedtls_milagro_free_octet(&milagro_cs->V);
    mbedtls_milagro_free_octet(&milagro_cs->H);
    mbedtls_milagro_free_octet(&milagro_cs->Key);
    mbedtls_milagro_free_octet(&milagro_cs->secret);
    mbedtls_milagro_cs_kill_csprng(&milagro_cs->RNG);
}


#endif /* MBEDTLS_MILAGRO_CS_C */



#if defined(MBEDTLS_MILAGRO_P2P_C)


int mbedtls_milagro_p2p_alloc_memory(int client_or_server, mbedtls_milagro_p2p_context *milagro_p2p)
{
    milagro_p2p->shared_secret.val = mbedtls_milagro_calloc(16);
    milagro_p2p->shared_secret.max = 16;
    milagro_p2p->client_PIA.val = mbedtls_milagro_calloc(PGS);
    milagro_p2p->client_PIA.max = PGS;
    milagro_p2p->client_PIB.val = mbedtls_milagro_calloc(PGS);
    milagro_p2p->client_PIB.max = PGS;
    
    if(client_or_server == MBEDTLS_MILAGRO_IS_SERVER)
    {
        milagro_p2p->X.val = mbedtls_milagro_calloc(PGS);
        milagro_p2p->X.max = PGS;
        milagro_p2p->server_pub_param_G1.val = mbedtls_milagro_calloc(2*PFS+1);
        milagro_p2p->server_pub_param_G1.max = 2*PFS+1;
    }
    else if(client_or_server == MBEDTLS_MILAGRO_IS_CLIENT)
    {
        milagro_p2p->W.val = mbedtls_milagro_calloc(PGS);
        milagro_p2p->W.max = PGS;
        milagro_p2p->Y.val = mbedtls_milagro_calloc(PGS);
        milagro_p2p->Y.max = PGS;
        milagro_p2p->client_pub_param_G1.val = mbedtls_milagro_calloc(2*PFS+1);
        milagro_p2p->client_pub_param_G1.max = 2*PFS+1;
        milagro_p2p->client_pub_param_G2.val = mbedtls_milagro_calloc(4*PFS);
        milagro_p2p->client_pub_param_G2.max = 4*PFS;
    }
    else
    {
        exit(MBEDTLS_ERR_MILAGRO_BAD_INPUT);
    }
    return 0;
}



void mbedtls_milagro_p2p_init(mbedtls_milagro_p2p_context * milagro_p2p)
{
    memset(milagro_p2p,0,sizeof(*milagro_p2p));
}


int mbedtls_milagro_p2p_set_identity(int client_or_server, mbedtls_milagro_p2p_context *milagro_p2p, char * identity)
{
    if(client_or_server == MBEDTLS_MILAGRO_IS_SERVER)
    {
        
        milagro_p2p->server_identity.val = mbedtls_milagro_calloc(strlen(identity));
        memcpy(milagro_p2p->server_identity.val, identity, strlen(identity));
        milagro_p2p->server_identity.len = (int)strlen(identity);
        milagro_p2p->server_identity.max = 256;
    }
    else if(client_or_server == MBEDTLS_MILAGRO_IS_CLIENT)
    {
        milagro_p2p->client_identity.val = mbedtls_milagro_calloc(strlen(identity));
        memcpy(milagro_p2p->client_identity.val, identity, strlen(identity));
        milagro_p2p->client_identity.len = (int)strlen(identity);
        milagro_p2p->client_identity.max = 256;
    }
    else
    {
        exit(MBEDTLS_ERR_MILAGRO_BAD_INPUT);
    }
    
    return 0;
}


void mbedtls_milagro_p2p_set_key(int client_or_server, mbedtls_milagro_p2p_context *milagro_p2p, char* key, int len_key)
{
    if(client_or_server == MBEDTLS_MILAGRO_IS_SERVER)
    {
        milagro_p2p->server_sen_key .val = mbedtls_milagro_calloc(256);
        memcpy(milagro_p2p->server_sen_key.val, key, len_key);
        milagro_p2p->server_sen_key.max = len_key;
        milagro_p2p->server_sen_key.len = len_key;

    }
    else if (client_or_server == MBEDTLS_MILAGRO_IS_CLIENT)
    {
        milagro_p2p->client_rec_key .val = mbedtls_milagro_calloc(256);
        memcpy(milagro_p2p->client_rec_key.val, key, len_key);
        milagro_p2p->client_rec_key.max = len_key;
        milagro_p2p->client_rec_key.len = len_key;
    }
    else
    {
        exit(MBEDTLS_ERR_MILAGRO_BAD_INPUT);
    }
}


int mbedtls_milagro_p2p_setup_RNG( mbedtls_milagro_p2p_context *milagro_p2p, mbedtls_entropy_context *entropy)
{
    unsigned char seed[20] = {0};
    char raw[100] = {0};
    
    octet RAW={0,sizeof(raw),raw};
    
    for (int i = 0; i<5; i++) {
        if (mbedtls_entropy_func(entropy, seed, 20) != 0)
        {
            return(MBEDTLS_ERR_ENTROPY_SOURCE_FAILED);
        }
        RAW.len=100;
        memcpy(RAW.val+i*20,&seed,20);
    }
    /* initialise strong RNG */
    mbedtls_milagro_p2p_create_csprng(&milagro_p2p->RNG,&RAW);
    
    return 0;
}



int mbedtls_milagro_p2p_compute_public_param( mbedtls_milagro_p2p_context *milagro_p2p)
{
    mbedtls_milagro_p2p_alloc_memory(MBEDTLS_MILAGRO_IS_SERVER, milagro_p2p);
    
    if (mbedtls_milagro_p2p_random_generate(&milagro_p2p->RNG,&milagro_p2p->X) != 0)
    {
        return(MBEDTLS_ERR_MILAGRO_P2P_PARAMETERS_COMPUTATOIN_FAILED);
    }
    if (mbedtls_milagro_p2p_get_g1_multiple(hashDoneOFF,&milagro_p2p->X,&milagro_p2p->server_identity,
                             &milagro_p2p->server_pub_param_G1) != 0)
    {
        return(MBEDTLS_ERR_MILAGRO_P2P_PARAMETERS_COMPUTATOIN_FAILED);
    }
    return 0;
}


int mbedtls_milagro_p2p_write_public_parameters(int client_or_server, mbedtls_milagro_p2p_context *milagro_p2p,
                                                unsigned char *buf, size_t len, size_t *param_len )
{
    unsigned char *p = buf;
    const unsigned char *end = buf + len;
    
    if(client_or_server == MBEDTLS_MILAGRO_IS_SERVER)
    {
        *p++ = (unsigned char)( ( ( milagro_p2p->server_identity.len     ) >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( ( milagro_p2p->server_identity.len     )      ) & 0xFF );
        *p++ = (unsigned char)( ( ( milagro_p2p->server_pub_param_G1.len     ) >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( ( milagro_p2p->server_pub_param_G1.len     )      ) & 0xFF );
        
        memcpy(p, milagro_p2p->server_identity.val, milagro_p2p->server_identity.len);
        p += milagro_p2p->server_identity.len;
        memcpy(p, milagro_p2p->server_pub_param_G1.val, milagro_p2p->server_pub_param_G1.len);
        p += milagro_p2p->server_pub_param_G1.len;
    }
    else if(client_or_server == MBEDTLS_MILAGRO_IS_CLIENT)
    {
        *p++ = (unsigned char)( ( ( milagro_p2p->client_identity.len     ) >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( ( milagro_p2p->client_identity.len     )      ) & 0xFF );
        *p++ = (unsigned char)( ( ( milagro_p2p->client_pub_param_G1.len     ) >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( ( milagro_p2p->client_pub_param_G1.len     )      ) & 0xFF );
        *p++ = (unsigned char)( ( ( milagro_p2p->client_pub_param_G2.len     ) >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( ( milagro_p2p->client_pub_param_G2.len     )      ) & 0xFF );
        
        memcpy(p, milagro_p2p->client_identity.val, milagro_p2p->client_identity.len);
        p += milagro_p2p->client_identity.len;
        memcpy(p, milagro_p2p->client_pub_param_G1.val, milagro_p2p->client_pub_param_G1.len);
        p += milagro_p2p->client_pub_param_G1.len;
        memcpy(p, milagro_p2p->client_pub_param_G2.val, milagro_p2p->client_pub_param_G2.len);
        p += milagro_p2p->client_pub_param_G2.len;
    }
    else
    {
        exit(MBEDTLS_ERR_MILAGRO_BAD_INPUT);
    }
    
    if( end < p )
    {
        return(MBEDTLS_ERR_MILAGRO_BAD_INPUT);
    }
    
    
    *param_len = p - buf;
    
    return 0;
}


int mbedtls_milagro_p2p_read_public_parameters( int client_or_server, mbedtls_milagro_p2p_context *milagro_p2p,
                                               const unsigned char *buf, size_t len  )
{
    if (client_or_server == MBEDTLS_MILAGRO_IS_CLIENT)
    {
        // Copy the length of the server_identity
        milagro_p2p->server_identity.len = UINT16_MAX & (buf[1] | ((uint16_t)buf[0])<< 8);
        milagro_p2p->server_identity.val = mbedtls_milagro_calloc(milagro_p2p->server_identity.len);
        milagro_p2p->server_identity.max = 256;
        
        // Copy the length of the parameter server_pub_param_G1
        milagro_p2p->server_pub_param_G1.len = UINT16_MAX & (buf[3] | ((uint16_t)buf[2])<< 8);
        milagro_p2p->server_pub_param_G1.max = milagro_p2p->server_pub_param_G1.len;
        milagro_p2p->server_pub_param_G1.val = mbedtls_milagro_calloc(milagro_p2p->server_pub_param_G1.len);
        
        //Copy the server_identity
        memcpy(milagro_p2p->server_identity.val, &buf[4], milagro_p2p->server_identity.len);
    
        //Copy the parameter server_pub_param_G1
        memcpy(milagro_p2p->server_pub_param_G1.val, &buf[4+milagro_p2p->server_identity.len],
               milagro_p2p->server_pub_param_G1.len);
        
        if ((int)len != milagro_p2p->server_identity.len +
            milagro_p2p->server_pub_param_G1.len + 4)
        {
            return(MBEDTLS_ERR_MILAGRO_P2P_READ_PARAM_FAILED);
        }
    }
    else if (client_or_server == MBEDTLS_MILAGRO_IS_SERVER)
    {
        // Copy the length of the client_identity
        milagro_p2p->client_identity.len = UINT16_MAX & (buf[1] | ((uint16_t)buf[0])<< 8);
        milagro_p2p->client_identity.val = mbedtls_milagro_calloc(milagro_p2p->client_identity.len);
        milagro_p2p->client_identity.max = 256;
        
        // Copy the length of the parameter client_pub_param_G1
        milagro_p2p->client_pub_param_G1.len = UINT16_MAX & (buf[3] | ((uint16_t)buf[2])<< 8);
        milagro_p2p->client_pub_param_G1.max = milagro_p2p->client_pub_param_G1.len;
        milagro_p2p->client_pub_param_G1.val = mbedtls_milagro_calloc(milagro_p2p->client_pub_param_G1.len);
        
        // Copy the length of the parameter client_pub_param_G2
        milagro_p2p->client_pub_param_G2.len = UINT16_MAX & (buf[5] | ((uint16_t)buf[4])<< 8);
        milagro_p2p->client_pub_param_G2.max = milagro_p2p->client_pub_param_G2.len;
        milagro_p2p->client_pub_param_G2.val = mbedtls_milagro_calloc(milagro_p2p->client_pub_param_G2.len);
        
        //Copy the client_identity
        memcpy(milagro_p2p->client_identity.val, &buf[6], milagro_p2p->client_identity.len);
        
        //Copy the parameter client_pub_param_G1
        memcpy(milagro_p2p->client_pub_param_G1.val, &buf[6 + milagro_p2p->client_identity.len],
               milagro_p2p->client_pub_param_G1.len);
        
        //Copy the parameter server_pub_param_G2
        memcpy(milagro_p2p->client_pub_param_G2.val, &buf[6 + milagro_p2p->client_identity.len +
                                                          milagro_p2p->client_pub_param_G1.len],
               milagro_p2p->client_pub_param_G2.len);
        
        if ((int)len != milagro_p2p->client_identity.len +
            milagro_p2p->client_pub_param_G1.len +
            milagro_p2p->client_pub_param_G2.len + 6)
        {
            return(MBEDTLS_ERR_MILAGRO_P2P_READ_PARAM_FAILED);
        }
    }
    else
    {
        return -1;
    }
    return 0;
}

int mbedtls_milagro_p2p_share_secret_cli(mbedtls_milagro_p2p_context *milagro_p2p)
{
    mbedtls_milagro_p2p_alloc_memory(MBEDTLS_MILAGRO_IS_CLIENT, milagro_p2p);
    if(mbedtls_milagro_p2p_random_generate(&milagro_p2p->RNG ,
                                           &milagro_p2p->W) != 0)
    {
        return (MBEDTLS_ERR_MILAGRO_P2P_PARAMETERS_COMPUTATOIN_FAILED);
    }
    if( mbedtls_milagro_p2p_get_g1_multiple(hashDoneOFF,&milagro_p2p->W,
                                            &milagro_p2p->server_identity,
                                            &milagro_p2p->client_pub_param_G1) != 0)
    {
        return (MBEDTLS_ERR_MILAGRO_P2P_PARAMETERS_COMPUTATOIN_FAILED);
    }
    if(mbedtls_milagro_p2p_random_generate(&milagro_p2p->RNG ,
                                           &milagro_p2p->Y) != 0)
    {
        return (MBEDTLS_ERR_MILAGRO_P2P_PARAMETERS_COMPUTATOIN_FAILED);
    }
    if(mbedtls_milagro_p2p_get_g2_multiple(hashDoneOFF,&milagro_p2p->Y,
                                           &milagro_p2p->client_identity,
                                           &milagro_p2p->client_pub_param_G2) != 0)
    {
        return (MBEDTLS_ERR_MILAGRO_P2P_PARAMETERS_COMPUTATOIN_FAILED);
    }
    mbedtls_milagro_p2p_hq(&milagro_p2p->server_pub_param_G1,
                           &milagro_p2p->client_pub_param_G2,
                           &milagro_p2p->client_pub_param_G1,
                           &milagro_p2p->client_identity,
                           &milagro_p2p->client_PIA);
    mbedtls_milagro_p2p_hq(&milagro_p2p->client_pub_param_G2,
                           &milagro_p2p->server_pub_param_G1,
                           &milagro_p2p->client_pub_param_G1,
                           &milagro_p2p->server_identity,
                           &milagro_p2p->client_PIB);
    if (mbedtls_milagro_p2p_receiver_key(milagro_p2p->date,
                                         &milagro_p2p->Y,
                                         &milagro_p2p->W,
                                         &milagro_p2p->client_PIA,
                                         &milagro_p2p->client_PIB,
                                         &milagro_p2p->server_pub_param_G1,
                                         &milagro_p2p->client_pub_param_G1,
                                         &milagro_p2p->client_rec_key, NULL,
                                         &milagro_p2p->server_identity,
                                         &milagro_p2p->shared_secret) != 0)
    {
        return (MBEDTLS_ERR_MILAGRO_P2P_MSECRET_COMPUTATOIN_FAILED);
    }

    return 0;
}

int mbedtls_milagro_p2p_share_secret_srv(mbedtls_milagro_p2p_context *milagro_p2p)
{
    mbedtls_milagro_p2p_hq(&milagro_p2p->server_pub_param_G1,
                           &milagro_p2p->client_pub_param_G2,
                           &milagro_p2p->client_pub_param_G1,
                           &milagro_p2p->client_identity,
                           &milagro_p2p->client_PIA);
    
    mbedtls_milagro_p2p_hq(&milagro_p2p->client_pub_param_G2,
                           &milagro_p2p->server_pub_param_G1,
                           &milagro_p2p->client_pub_param_G1,
                           &milagro_p2p->server_identity,
                           &milagro_p2p->client_PIB);
    
    if (mbedtls_milagro_p2p_sender_key(milagro_p2p->date,
                                       &milagro_p2p->X,
                                       &milagro_p2p->client_PIA,
                                       &milagro_p2p->client_PIB,
                                       &milagro_p2p->client_pub_param_G2,
                                       &milagro_p2p->client_pub_param_G1,
                                       &milagro_p2p->server_sen_key, NULL,
                                       &milagro_p2p->client_identity,
                                       &milagro_p2p->shared_secret) != 0)
    {
        return (MBEDTLS_ERR_MILAGRO_P2P_MSECRET_COMPUTATOIN_FAILED);
    }
    
    return 0;
}

void mbedtls_milagro_p2p_free( mbedtls_milagro_p2p_context *milagro_p2p)
{
    if(!milagro_p2p)
        return;
    
    mbedtls_milagro_free_octet(&milagro_p2p->client_identity);
    mbedtls_milagro_free_octet(&milagro_p2p->server_identity);
    mbedtls_milagro_free_octet(&milagro_p2p->client_PIA);
    mbedtls_milagro_free_octet(&milagro_p2p->client_PIB);
    mbedtls_milagro_free_octet(&milagro_p2p->client_pub_param_G1);
    mbedtls_milagro_free_octet(&milagro_p2p->client_pub_param_G2);
    mbedtls_milagro_free_octet(&milagro_p2p->server_pub_param_G1);
    mbedtls_milagro_free_octet(&milagro_p2p->shared_secret);
    mbedtls_milagro_free_octet(&milagro_p2p->client_rec_key);
    mbedtls_milagro_free_octet(&milagro_p2p->server_sen_key);
    mbedtls_milagro_free_octet(&milagro_p2p->W);
    mbedtls_milagro_free_octet(&milagro_p2p->X);
    mbedtls_milagro_free_octet(&milagro_p2p->Y);
    mbedtls_milagro_p2p_kill_csprng(&milagro_p2p->RNG);
}

#endif /* MBEDTLS_MILAGRO_P2P_C */
