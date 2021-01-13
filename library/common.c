/*
 *  Internal invasive testing helper functions
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

#include "common.h"

#include <stddef.h>

#if defined(MBEDTLS_TEST_HOOKS)
static void (*err_add_hook)( int, int, const char *, int );
void mbedtls_set_err_add_hook(void *hook)
{
    err_add_hook = hook;
}
int mbedtls_err_add( int high, int low, const char *file, int line )
{
    if( err_add_hook != NULL )
        (*err_add_hook)( high, low, file, line );
    return ( high + low );
}
#endif
