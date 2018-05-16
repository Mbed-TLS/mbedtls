
#include "../../include/mbedtls/mps/trace.h"
#include <stdio.h>

static int trace_depth_ = 0;

#define color_default  "\x1B[0m"
#define color_red      "\x1B[1;31m"
#define color_green    "\x1B[1;32m"
#define color_yellow   "\x1B[1;33m"
#define color_blue     "\x1B[1;34m"
#define color_magenta  "\x1B[1;35m"
#define color_cyan     "\x1B[1;36m"
#define color_white    "\x1B[1;37m"

static char const * colors[] =
{
    color_default,
    color_green,
    color_yellow,
    color_magenta,
    color_cyan,
    color_white
};

int get_trace_depth()
{
    return trace_depth_;
}
void dec_trace_depth()
{
    trace_depth_--;
}
void inc_trace_depth()
{
    trace_depth_++;
}

void trace_color( int id )
{
    if( id > (int) ( sizeof( colors ) / sizeof( *colors ) ) )
        return;
    printf( "%s", colors[ id ] );
}

void trace_indent( int level, trace_type ty )
{
    if( level > 0 )
    {
        while( --level )
            printf( "|  " );
        printf( "|--" );
    }

    switch( ty )
    {
        case trace_comment:
            printf( "@ " );
            break;

        case trace_call:
            printf( "+ " );
            break;

        case trace_error:
            printf( "E " );
            break;

        default:
            break;
    }
}
