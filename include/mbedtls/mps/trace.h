
#ifndef MBEDTLS_MPS_TRACE_H
#define MBEDTLS_MPS_TRACE_H

/*
 * Adapt this to enable/disable tracing output
 * from the various layers of the MPS.
 */

#define TRACE_ENABLE_LAYER_1
#define TRACE_ENABLE_LAYER_2
#define TRACE_ENABLE_LAYER_3
#define TRACE_ENABLE_LAYER_4
#define TRACE_ENABLE_READER
#define TRACE_ENABLE_WRITER

/*
 * To use the existing trace module, only change
 * TRACE_ENABLE_XXX above, but don't modify the
 * rest of this file.
 */

__attribute__((unused)) static int trace_id;

typedef enum
{
    trace_comment,
    trace_call,
    trace_error
} trace_type;

#define TRACE_BIT_LAYER_1 1
#define TRACE_BIT_LAYER_2 2
#define TRACE_BIT_LAYER_3 3
#define TRACE_BIT_LAYER_4 4
#define TRACE_BIT_WRITER  5
#define TRACE_BIT_READER  6

#if defined(TRACE_ENABLE_LAYER_1)
#define TRACE_MASK_LAYER_1 (1u << TRACE_BIT_LAYER_1 )
#else
#define TRACE_MASK_LAYER_1 0
#endif

#if defined(TRACE_ENABLE_LAYER_2)
#define TRACE_MASK_LAYER_2 (1u << TRACE_BIT_LAYER_2 )
#else
#define TRACE_MASK_LAYER_2 0
#endif

#if defined(TRACE_ENABLE_LAYER_3)
#define TRACE_MASK_LAYER_3 (1u << TRACE_BIT_LAYER_3 )
#else
#define TRACE_MASK_LAYER_3 0
#endif

#if defined(TRACE_ENABLE_LAYER_4)
#define TRACE_MASK_LAYER_4 (1u << TRACE_BIT_LAYER_4 )
#else
#define TRACE_MASK_LAYER_4 0
#endif

#if defined(TRACE_ENABLE_READER)
#define TRACE_MASK_READER (1u << TRACE_BIT_READER )
#else
#define TRACE_MASK_READER 0
#endif

#if defined(TRACE_ENABLE_WRITER)
#define TRACE_MASK_WRITER (1u << TRACE_BIT_WRITER )
#else
#define TRACE_MASK_WRITER 0
#endif

#define TRACE_MASK ( TRACE_MASK_LAYER_1 |           \
                     TRACE_MASK_LAYER_2 |           \
                     TRACE_MASK_LAYER_3 |           \
                     TRACE_MASK_LAYER_4 |           \
                     TRACE_MASK_READER  |           \
                     TRACE_MASK_WRITER )

/* We have to avoid globals because E-ACSL chokes on them...
 * Wrap everything in stub functions. */
int get_trace_depth( void );
void inc_trace_depth( void );
void dec_trace_depth( void );

void trace_color( int id );
void trace_indent( int level, trace_type ty );

#define TRACE( type, fmt, ... )                                         \
    do {                                                                \
        if( ! ( TRACE_MASK & ( 1u << trace_id ) ) )                     \
            break;                                                      \
        trace_indent( get_trace_depth(), type );                        \
        trace_color( trace_id );                                        \
        printf( "[%d|L%u]: " fmt "\n", trace_id, __LINE__, ##__VA_ARGS__); \
        trace_color( 0 );                                               \
    } while( 0 )

#define TRACE_INIT( fmt, ... )                                          \
    do {                                                                \
        if( ! ( TRACE_MASK & ( 1u << trace_id ) ) )                     \
            break;                                                      \
        TRACE( trace_call, fmt, ##__VA_ARGS__ );                        \
        inc_trace_depth();                                              \
    } while( 0 )

#define TRACE_END()                                                     \
    do {                                                                \
        if( ! ( TRACE_MASK & ( 1u << trace_id ) ) )                     \
            break;                                                      \
        dec_trace_depth();                                              \
    } while( 0 )

#define RETURN( val )                           \
    do {                                        \
        /* Breaks tail recursion. */            \
        int ret__ = val;                        \
        TRACE_END();                            \
        return( ret__ );                        \
    } while( 0 )

#endif /* MBEDTLS_MPS_TRACE_H */
