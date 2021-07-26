/**
 * \file inst.h
 *
 * \brief Instrumentation macros.
 * 
 * This file contains the `MBEDTLS_INST` instrumentation macros. These macros
 * provide a means for tracking temporal invocations, contexts, and payload
 * length in bytes. Each macro prints a valid JSON object prefixed with `inst`.
 * A post-processor can then reassemble these calls and reconstruct useful
 * information. Grep for `MBEDTLS_INST` in `library/` for examples how
 * they are deployed.
 * 
 * Each macro is named according to the paramters it accepts. Currently there
 * are now constraints on the free-form string fields, but in general they
 * follow this convention:
 * 
 *     prim  - The name of the cryptographic primitive that is executing.
 *     op    - The name of the operation, it may be an operation of a primitive,
 *             such as SHA `init`, or AES `free`. Or it may be any string if it
 *             is not part of a primitive.
 *     ctx   - A pointer to a context.
 *     ctx2  - A pointer to another context if the operation relates two.
 *     bytes - If the prim/op has a length field, the byte count. 
 *
 * Instrumentation is enabled by defining `MBEDTLS_INST` during compilation.
 * Output is written using `mbedtls_printf`, which may be configured by the
 * platform configuration, or set to `printf` in this header.
 * 
 */
/*
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
#ifndef MBEDTLS_INST_H
#define MBEDTLS_INST_H

#if defined(MBEDTLS_INST)

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */

#define MBEDTLS_INST_OP_CTX( op, ctx ) { \
    mbedtls_printf( \
        "\ninst{" \
        "\"op\": \"%s\", \"ctx\": \"%p\"" \
        "}\n", \
        op, ctx ); \
    }

#define MBEDTLS_INST_OP_CTX_CTX( op, ctx, ctx2 ) { \
    mbedtls_printf( \
        "\ninst{" \
        "\"op\": \"%s\",\"ctx\": \"%p\",\"ctx2\": \"%p\"" \
        "}\n", \
        op, ctx, ctx2 ); \
    }

#define MBEDTLS_INST_PRIM_OP_CTX( prim, op, ctx ) { \
    mbedtls_printf( \
        "\ninst{" \
        "\"prim\": \"%s\",\"op\": \"%s\",\"ctx\": \"%p\"" \
        "}\n", \
        prim, op, ctx ); \
    }

#define MBEDTLS_INST_PRIM_OP_CTX_CTX( prim, op, ctx, ctx2 ) { \
    mbedtls_printf( \
        "\ninst{" \
        "\"prim\": \"%s\",\"op\": \"%s\",\"ctx\": \"%p\",\"ctx2\": \"%p\"" \
        "}\n", \
        prim, op, ctx, ctx2 ); \
    }

#define MBEDTLS_INST_PRIM_OP_CTX_BYTES( prim, op, ctx, bytes ) { \
    mbedtls_printf( \
        "\ninst{" \
        "\"prim\": \"%s\",\"op\": \"%s\",\"ctx\": \"%p\",\"bytes\": %ld" \
        "}\n", \
        prim, op, ctx, (unsigned long)bytes ); \
    }

#else

#define MBEDTLS_INST_OP_CTX( op, ctx ) {}
#define MBEDTLS_INST_OP_CTX_CTX( op, ctx, ctx2 ) {}
#define MBEDTLS_INST_PRIM_OP_CTX( prim, op, ctx ) {}
#define MBEDTLS_INST_PRIM_OP_CTX_CTX( prim, op, ctx, ctx2 ) {}
#define MBEDTLS_INST_PRIM_OP_CTX_BYTES( prim, op, ctx, bytes ) {}

#endif /* MBEDTLS_INST */

#endif /* MBEDTLS_INST_H */