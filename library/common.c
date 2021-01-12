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

#if defined(MBEDTLS_TEST_HOOKS)
void (*mbedtls_test_err_add_hook)( int, int, const char *, int );
int mbedtls_err_add( int high, int low, const char *file, int line ) {
    if( mbedtls_test_err_add_hook != NULL )
        (*mbedtls_test_err_add_hook)( high, low, file, line );
    return ( high + low );
}
#endif
