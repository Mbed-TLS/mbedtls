/* Common definitions used for clients and services */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "psa/service.h"

#define PRINT(fmt, ...) \
    fprintf(stdout, fmt "\n", ##__VA_ARGS__)

#if defined(DEBUG)
#define INFO(fmt, ...) \
    fprintf(stdout, "Info (%s - %d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define ERROR(fmt, ...) \
    fprintf(stdout, "Error (%s - %d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define FATAL(fmt, ...) \
    { \
        fprintf(stdout, "Fatal (%s - %d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        abort(); \
    }
#else /* DEBUG */
#define INFO(...)
#define ERROR(...)
#define FATAL(...)
#endif /* DEBUG*/

#define PROJECT_ID              'M'
#define PATHNAMESIZE            256
#define TMP_FILE_BASE_PATH      "./"
