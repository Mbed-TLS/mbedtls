
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
 * TA_p2p.c
 *
 * Simuation of the Trusted Authorities that generate the
 * client and server's secret for milagro_p2p
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "wcc.h"


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


int main()
{
    int i,rtn,hashDoneOn = 1;
    
    /* Master secret */
    char ms[PGS];
    octet MS={sizeof(ms),sizeof(ms),ms};
    
    char hv[HASH_BYTES],server_id[256],client_id[256];
    octet HV={0,sizeof(hv),hv};
    
    octet IdS={0,sizeof(server_id),server_id};
    octet IdC={0,sizeof(client_id),client_id};
    
    // server keys
    char skeyG1[2*PFS+1];
    octet SkeyG1={0,sizeof(skeyG1), skeyG1};
    
    // client keys
    char ckeyG2[4*PFS];
    octet CkeyG2={0,sizeof(ckeyG2), ckeyG2};
    
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
    
    /* initialise random number generator */
    WCC_CREATE_CSPRNG(&RNG,&SEED);
    
    /* TA: Generate master secret  */
    rtn = WCC_RANDOM_GENERATE(&RNG,&MS);
    if (rtn != 0) {
        printf("TA WCC_RANDOM_GENERATE(&RNG,&MS) Error %d\n", rtn);
        return 1;
    }
    
    printf("TA MASTER SECRET: ");
    OCT_output(&MS);
    printf("\n");
    
    // Server's ID
    OCT_jstring(&IdS,(char *)"server.miracl.com");
    
    // TA: Generate Servers's key
    WCC_HASH_ID(&IdS,&HV);
    rtn = WCC_GET_G1_MULTIPLE(hashDoneOn,&MS,&HV,&SkeyG1);
    if (rtn != 0) {
        printf("TA WCC_GET_G1_MULTIPLE() Error %d\n", rtn);
        return 1;
    }
    
    printf("TA Server's key: ");
    OCT_output(&SkeyG1);
    printf("\n");
    
    // Client's ID
    OCT_jstring(&IdC,(char *)"client@miracl.com");
    
    // TA: Generate Client's key
    WCC_HASH_ID(&IdC,&HV);
    rtn = WCC_GET_G2_MULTIPLE(hashDoneOn,&MS,&HV,&CkeyG2);
    if (rtn != 0) {
        printf("TA WCC_GET_G2_MULTIPLE() Error %d\n", rtn);
        return 1;
    }
    
    printf("TA Client's receiver key: ");
    OCT_output(&CkeyG2);
    printf("\n");
    
    write_to_file("P2PClientKey", CkeyG2);
    
    write_to_file("P2PServerKey",SkeyG1);
    
    
    return 0;
}
