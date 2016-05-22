
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
  *
  *
  * Simuation of the Trusted Authorities that generate the 
  * client and server's secret for milagro_cs
  *
  */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mpin.h"
#include "mbedtls/config.h"


int write_to_file(const char * path, octet to_write)
{
    unsigned char * string = calloc(to_write.len+1,sizeof(char));
    FILE * file = fopen(path,"w");
    if(!file || !string)
    {
        exit(EXIT_FAILURE);
    }
    OCT_toStr(&to_write, (char*)string);
    for (int i = 0; i<to_write.len; i++) {
        fprintf(file, "%02x", string[i]);
    }
    fclose(file);
    
    return 0;
}



int main(){
    
    int rtn, i, PIN;

    const char* user;
    
    /* Master secret shares */
    char ms1[PGS];
    octet MS1={sizeof(ms1),sizeof(ms1),ms1};
    
    /* Client Identity and its hash */
    char client_id[100], hash_id[HASH_BYTES];
    octet CLIENT_ID={0,sizeof(client_id),client_id};
    octet HASH_ID={0,sizeof(hash_id),hash_id};
    
    /* Server secret and shares */
    char serverSecret[4*PFS];
    octet ServerSecret={sizeof(serverSecret),sizeof(serverSecret),serverSecret};

#if defined(MBEDTLS_TLS_MILAGRO_CS_TIME_PERMITS)
    /* Time Permit and shares */
    char tp[2*PFS+1];
    octet TP={sizeof(tp),sizeof(tp),tp};
    int date = MPIN_today();
#endif
    
    /* Token stored on computer */
    char token[2*PFS+1];
    octet TOKEN={sizeof(token),sizeof(token),token};
    
    
    /* Random generator */
    char seed[32] = {0};
    octet SEED = {0,sizeof(seed),seed};
    csprng RNG;
    
    /* unrandom seed value! */
    SEED.len=32;
    for (i=0;i<32;i++) SEED.val[i]=i+1;
#ifdef DEBUG
    printf("SEED: ");
    OCT_output(&SEED);
    printf("\n");
#endif

    MPIN_CREATE_CSPRNG(&RNG,&SEED);
    
    /* Assign the End-User an ID */
    user = "client@miracl.com";
    OCT_jstring(&CLIENT_ID, (char*)user);
    
    /* Hash CLIENT_ID */
    MPIN_HASH_ID(&CLIENT_ID,&HASH_ID);
    
    /* master secret */
    rtn = MPIN_RANDOM_GENERATE(&RNG,&MS1);
    if (rtn != 0)
    {
        printf("MILAGRO_CS_RANDOM_GENERATE(&RNG,&MS1) Error %d\n", rtn);
        return 1;
    }

    /* server secret */
    rtn = MPIN_GET_SERVER_SECRET(&MS1,&ServerSecret);
    if (rtn != 0)
    {
        printf("MILAGRO_CS_GET_SERVER_SECRET(&MS1,&SS1) Error %d\n", rtn);
        return 1;
    }
    printf("Server Secret = 0x");
    OCT_output(&ServerSecret);
    
    /* client secret */
    rtn = MPIN_GET_CLIENT_SECRET(&MS1,&HASH_ID,&TOKEN);
    if (rtn != 0)
    {
        printf("MILAGRO_CS_GET_CLIENT_SECRET(&MS1,&HASH_ID,&CS1) Error %d\n", rtn);
        return 1;
    }
    printf("Client Secret = 0x");
    OCT_output(&TOKEN);

#if defined(MBEDTLS_TLS_MILAGRO_CS_TIME_PERMITS)
    /* Generate Time Permits */
    rtn = MPIN_GET_CLIENT_PERMIT(date,&MS1,&HASH_ID,&TP);
    if (rtn != 0)
    {
        printf("MILAGRO_CS_GET_CLIENT_PERMIT(date,&MS1,&HASH_ID,&TP1) Error %d\n", rtn);
        return 1;
    }
    printf("\nTime Permit = 0x");
    OCT_output(&TP);
#endif
#if defined(MBEDTLS_TLS_MILAGRO_CS_ENABLE_PIN)
    /* Client extracts PIN from secret to create Token */
    PIN = 1234;
#else
    PIN = 0;
#endif
    rtn = MPIN_EXTRACT_PIN(&HASH_ID, PIN, &TOKEN);
    if (rtn != 0)
    {
        printf("MILAGRO_CS_EXTRACT_PIN( &HASH_ID, PIN, &TOKEN) Error %d\n", rtn);
        return 1;
    }
    printf("\nToken = 0x");
    OCT_output(&TOKEN);
    
#if defined(MBEDTLS_TLS_MILAGRO_CS_TIME_PERMITS)
    write_to_file("CSTimePermit", TP);
#endif
    write_to_file("CSServerKey", ServerSecret);
    
    write_to_file("CSClientKey", TOKEN);
    
    return 0;
}







