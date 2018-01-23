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
