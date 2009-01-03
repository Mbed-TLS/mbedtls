/**
 * \file debug.h
 */
#ifndef SSL_DEBUG_H
#define SSL_DEBUG_H

#include "xyssl/config.h"
#include "xyssl/ssl.h"

#if defined(XYSSL_DEBUG_MSG)

#define SSL_DEBUG_MSG( level, args )                    \
    debug_print_msg( ssl, level, __FILE__, __LINE__, debug_fmt args );

#define SSL_DEBUG_RET( level, text, ret )                \
    debug_print_ret( ssl, level, __FILE__, __LINE__, text, ret );

#define SSL_DEBUG_BUF( level, text, buf, len )           \
    debug_print_buf( ssl, level, __FILE__, __LINE__, text, buf, len );

#define SSL_DEBUG_MPI( level, text, X )                  \
    debug_print_mpi( ssl, level, __FILE__, __LINE__, text, X );

#define SSL_DEBUG_CRT( level, text, crt )                \
    debug_print_crt( ssl, level, __FILE__, __LINE__, text, crt );

#else

#define SSL_DEBUG_MSG( level, args )            do { } while( 0 )
#define SSL_DEBUG_RET( level, text, ret )       do { } while( 0 )
#define SSL_DEBUG_BUF( level, text, buf, len )  do { } while( 0 )
#define SSL_DEBUG_MPI( level, text, X )         do { } while( 0 )
#define SSL_DEBUG_CRT( level, text, crt )       do { } while( 0 )

#endif

#ifdef __cplusplus
extern "C" {
#endif

char *debug_fmt( const char *format, ... );

void debug_print_msg( ssl_context *ssl, int level,
                      char *file, int line, char *text );

void debug_print_ret( ssl_context *ssl, int level,
                      char *file, int line, char *text, int ret );

void debug_print_buf( ssl_context *ssl, int level,
                      char *file, int line, char *text,
                      unsigned char *buf, int len );

void debug_print_mpi( ssl_context *ssl, int level,
                      char *file, int line, char *text, mpi *X );

void debug_print_crt( ssl_context *ssl, int level,
                      char *file, int line, char *text, x509_cert *crt );

#ifdef __cplusplus
}
#endif

#endif /* debug.h */
