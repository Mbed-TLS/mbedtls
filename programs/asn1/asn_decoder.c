/*
 *  \brief  Converts BER encoded data to human readable format
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <limits.h>

#if defined(MBEDTLS_ASN1_PARSE_C) && defined(MBEDTLS_FS_IO)
#include "mbedtls/asn1.h"
#endif

#if !defined(MBEDTLS_ASN1_PARSE_C) || !defined(MBEDTLS_FS_IO)
int main(void)
{
    mbedtls_printf("MBEDTLS_ASN1_PARSE_C not defined.\n");
    mbedtls_exit(0);
}
#else

#define USAGE   \
    "\n  asn_decoder <input filename>\n" \
    "\n  example: asn_decoder file\n" \
    "\n"

static const char *tag_number_to_names(int tag_number)
{
    const char *tag_name;
    switch (tag_number) {
        case MBEDTLS_ASN1_BOOLEAN:
            tag_name = "BOOLEAN";
            break;
        case MBEDTLS_ASN1_INTEGER:
            tag_name = "INTEGER";
            break;
        case MBEDTLS_ASN1_BIT_STRING:
            tag_name = "BIT_STRING";
            break;
        case MBEDTLS_ASN1_OCTET_STRING:
            tag_name = "OCTET_STRING";
            break;
        case MBEDTLS_ASN1_NULL:
            tag_name = "NULL";
            break;
        case MBEDTLS_ASN1_OID:
            tag_name = "OID";
            break;
        case MBEDTLS_ASN1_ENUMERATED:
            tag_name = "ENUMERATED";
            break;
        case MBEDTLS_ASN1_UTF8_STRING:
            tag_name = "UTF8_STRING";
            break;
        case MBEDTLS_ASN1_SEQUENCE:
            tag_name = "SEQUENCE";
            break;
        case MBEDTLS_ASN1_SET:
            tag_name = "SET";
            break;
        case MBEDTLS_ASN1_PRINTABLE_STRING:
            tag_name = "PRINTABLE_STRING";
            break;
        case MBEDTLS_ASN1_T61_STRING:
            tag_name = "T61_STRING";
            break;
        case MBEDTLS_ASN1_IA5_STRING:
            tag_name = "IA5_STRING";
            break;
        case MBEDTLS_ASN1_UTC_TIME:
            tag_name = "UTC_TIME";
            break;
        case MBEDTLS_ASN1_GENERALIZED_TIME:
            tag_name = "GENERALIZED_TIME";
            break;
        case MBEDTLS_ASN1_UNIVERSAL_STRING:
            tag_name = "UNIVERSAL_STRING";
            break;
        case MBEDTLS_ASN1_BMP_STRING:
            tag_name = "BMP_STRING";
            break;
        default:
            tag_name = "UNKNOWN";
    }
    return tag_name;
}

static int ber_to_string(unsigned char **input, size_t length, int depth)
{
    int number, constructed, class;
    const char *tag_name;
    size_t inner_length;
    int ret;
    unsigned int i;
    unsigned char *content = NULL;
    unsigned char *end = (*input) + length;

    while (*input < end) {
        if ((ret = mbedtls_asn1_get_any_tag(input, end, &number, &constructed, &class)) != 0) {
            return -1;
        }
        if ((ret = mbedtls_asn1_get_len(input, end, &inner_length)) != 0) {
            return -1;
        }

        if (class == MBEDTLS_ASN1_UNIVERSAL) {
            tag_name = tag_number_to_names(number);
            printf("%*s ", depth*4 + (int) strlen(tag_name), tag_name);
        } else if (class == MBEDTLS_ASN1_APPLICATION) {
            printf("%*s[APPLICATION %d] ", depth*4, "", number);
        } else {
            printf("%*s[%d] ", depth*4, "", number);
        }

        if (inner_length + (*input) > end) {
            return -1;
        } else if (constructed == MBEDTLS_ASN1_CONSTRUCTED) {
            printf("{ \n");
            if ((ret = ber_to_string(input, inner_length, depth + 1)) != 0) {
                return ret;
            }
            printf("%*s}\n", depth*4, "");
        } else {
            content = malloc(inner_length);
            /* Do some stuff with the content based on tag */
            content = memcpy(content, *input, inner_length);
            *input += inner_length;
            if (MBEDTLS_ASN1_IS_STRING_TAG((unsigned int) number) &&
                (number != MBEDTLS_ASN1_BIT_STRING) &&
                (class == MBEDTLS_ASN1_UNIVERSAL)) {
                printf("\"");
                for (i = 0; i < inner_length; i++) {
                    printf("%c", content[i]);
                }
                printf("\"");
            } else {
                printf("0x");
                for (i = 0; i < inner_length; i++) {
                    printf("%X", content[i]);
                }
            }
            printf("\n");
            free(content);
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    FILE *fp = NULL;
    int exit_code = MBEDTLS_EXIT_FAILURE, ret;
    long file_length;
    unsigned char *input_buf = NULL;
    unsigned char *s;

    if (argc != 2) {
        mbedtls_printf(USAGE);
        goto exit;
    }

    if ((fp = fopen(argv[1], "rb")) == NULL) {
        mbedtls_fprintf(stderr, "fopen(%s,rb) failed\n", argv[1]);
        goto exit;
    }

    fseek(fp, 0L, SEEK_END);
    file_length = ftell(fp);
    rewind(fp);

    input_buf = calloc(1, file_length+1);
    s = input_buf;

    while (fread(input_buf, file_length, 1, fp) != 1) {
    }

    ret = ber_to_string(&s, file_length, 0);

    if (ret == -1) {
#if PTRDIFF_MAX == INT_MAX
        printf("Invalid data, error at byte %d\n", s - input_buf);
#elif PTRDIFF_MAX == LONG_MAX
        printf("Invalid data, error at byte %ld\n", s - input_buf);
#elif PTRDIFF_MAX == LLONG_MAX
#if defined(_WIN32)
        printf("Invalid data, error at byte %I64u\n", s - input_buf);
#else
        printf("Invalid data, error at byte %lld\n", s - input_buf);
#endif
#endif
    }

exit:
    if (fp) {
        fclose(fp);
    }
    if (input_buf) {
        mbedtls_free(input_buf);
    }
    mbedtls_exit(exit_code);
}

#endif
