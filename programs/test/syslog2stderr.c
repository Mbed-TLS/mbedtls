/** \brief Syslog to stderr wrapper for Unix-like systems
 *
 * By dynamically linking this module into an executable, any message sent to the system logs
 * via the POSIX or Linux API is instead redirected to standard error.
*
* Compile this program with `cc -fPID -shared -o syslog2stderr.so syslog2stderr.c -ldl`
* and load it dynamically when running `myprogram` with
* `LD_PRELOAD=/path/to/syslog2stderr.so myprogram`.
* On macOS, replace `LD_PRELOAD` by `DYLD_PRELOAD`.
 */
 /**  
 *  Copyright (C) 2017-2018, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>


void openlog( const char *ident, int option, int facility )
{
    (void) ident;
    (void) option;
    (void) facility;
}

/* POSIX API */
void syslog( int priority, const char *format, ... )
{
    va_list args;
    va_start( args, format );
    vfprintf( stderr, format, args );
    va_end( args );
}

/* Linux ABI
 * http://refspecs.linux-foundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/libc---syslog-chk-1.html
 */
void __syslog_chk( int priority, int flag, const char *format, ... )
{
    va_list args;
    (int) flag;
    va_start( args, format );
    vfprintf( stderr, format, args );
    fputc( '\n', stderr );
    va_end( args );
}

void closelog( void )
{
    /* no-op */
}
