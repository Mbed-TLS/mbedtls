/* PSA status codes used by psasim. */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_ERROR_H
#define PSA_ERROR_H
#include <stdint.h>
typedef int32_t psa_status_t;

#define PSA_SUCCESS                     ((psa_status_t) 0)

#define PSA_ERROR_PROGRAMMER_ERROR      ((psa_status_t) -129)
#define PSA_ERROR_CONNECTION_REFUSED    ((psa_status_t) -130)
#define PSA_ERROR_CONNECTION_BUSY       ((psa_status_t) -131)
#define PSA_ERROR_GENERIC_ERROR         ((psa_status_t) -132)
#define PSA_ERROR_NOT_PERMITTED         ((psa_status_t) -133)
#define PSA_ERROR_NOT_SUPPORTED         ((psa_status_t) -134)
#define PSA_ERROR_INVALID_ARGUMENT      ((psa_status_t) -135)
#define PSA_ERROR_INVALID_HANDLE        ((psa_status_t) -136)
#define PSA_ERROR_BAD_STATE             ((psa_status_t) -137)
#define PSA_ERROR_BUFFER_TOO_SMALL      ((psa_status_t) -138)
#define PSA_ERROR_ALREADY_EXISTS        ((psa_status_t) -139)
#define PSA_ERROR_DOES_NOT_EXIST        ((psa_status_t) -140)
#define PSA_ERROR_INSUFFICIENT_MEMORY   ((psa_status_t) -141)
#define PSA_ERROR_INSUFFICIENT_STORAGE  ((psa_status_t) -142)
#define PSA_ERROR_INSUFFICIENT_DATA     ((psa_status_t) -143)
#define PSA_ERROR_SERVICE_FAILURE       ((psa_status_t) -144)
#define PSA_ERROR_COMMUNICATION_FAILURE ((psa_status_t) -145)
#define PSA_ERROR_STORAGE_FAILURE       ((psa_status_t) -146)
#define PSA_ERROR_HARDWARE_FAILURE      ((psa_status_t) -147)
#define PSA_ERROR_INVALID_SIGNATURE     ((psa_status_t) -149)

#endif
