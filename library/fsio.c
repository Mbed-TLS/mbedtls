/*
 *  Serialization based implementation of filesystem IO functions.
 *
 *  Copyright (C) 2017, ARM Limited, All Rights Reserved
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_FS_IO)

#include "mbedtls/fsio.h"

#if !defined(MBEDTLS_FS_IO_ALT)

/**
 * \brief          Open file and disable buffering.
 *
 * \param path     File path
 * \param mode     Open mode
 *
 * \return         Pointer to mbedtls_file_t on success or NULL on failure.
 */
mbedtls_file_t * mbedtls_fopen( const char *path, const char *mode )
{
    mbedtls_file_t * f = fopen( path, mode );

    if( f && ( setvbuf( f, NULL, _IONBF, 0 ) != 0 ) )
    {
        fclose( f );
        f = NULL;
    }

    return( f );
}

#else /* !MBEDTLS_FS_IO_ALT */

#if defined(MBEDTLS_SERIALIZE_C)
#include <string.h>

#include "mbedtls/serialize.h"



#define INT_TO_FILE_PTR( x ) ( (mbedtls_file_t *)(uintptr_t)x )
#define FILE_PTR_TO_INT( x ) ( (int32_t)(uintptr_t)x )

/**
 * \brief          Open file. Follows standard C fopen interface.
 *
 * \param path     File path
 * \param mode     Open mode
 *
 * \return         Pointer to mbedtls_file_t on success or NULL on failure.
 */
mbedtls_file_t * mbedtls_fopen( const char *path, const char *mode )
{
    int status;
    uint32_t file_id;
    mbedtls_file_t * file = NULL;
    mbedtls_serialize_push_buffer( path, strlen( path ) + 1 );
    mbedtls_serialize_push_buffer( mode, strlen( mode ) + 1 );
    status = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FOPEN );

    if ( status == 0 )
    {
        mbedtls_serialize_pop_int32( &file_id ); /* Id */
        file = INT_TO_FILE_PTR( file_id );
    }
    return( file );
}

/**
 * \brief          Read file. Follows standard C fread interface.
 *
 * \param ptr      Pointer to output buffer
 * \param size     Size of read items.
 * \param nmemb    Number of read items.
 * \param stream   Pointer to mbedtls_file_t.
 *
 * \return         Number of items read.
 */
size_t mbedtls_fread( void *ptr, size_t size, size_t nmemb,
                      mbedtls_file_t *stream )
{
    int status;
    size_t ret = -1;

    /* Only byte size items allowed */
    if ( size != 1 )
        return -1;

    mbedtls_serialize_push_int32( FILE_PTR_TO_INT( stream ) );
    mbedtls_serialize_push_int32( nmemb );
    status = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FREAD );
    if ( status == 0 )
        mbedtls_serialize_pop_buffer( ptr, nmemb, &ret );
    return( ret );
}

/**
 * \brief          Write file. Follows standard C fwrite interface.
 *
 * \param ptr      Pointer to input buffer
 * \param size     Size of write items.
 * \param nmemb    Number of write items.
 * \param stream   Pointer to mbedtls_file_t.
 *
 * \return         Number of items written.
 */
size_t mbedtls_fwrite( const void *ptr, size_t size, size_t nmemb,
                       mbedtls_file_t *stream )
{
    int status;
    uint32_t written = 0;
    size_t ret = -1;

    /* Only byte size items allowed */
    if ( size != 1 )
        return( -1 );

    mbedtls_serialize_push_int32( FILE_PTR_TO_INT( stream ) );
    mbedtls_serialize_push_buffer( ptr, nmemb );
    status = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FWRITE );
    if ( status == 0 )
    {
        mbedtls_serialize_pop_int32( &written );
        ret = written;
    }
    return( ret );
}

/**
 * \brief          Reads a line from file. Follows standard C fgets interface.
 *
 * \param s        Pointer to output buffer.
 * \param size     Size of buffer.
 * \param stream   Pointer to mbedtls_file_t.
 *
 * \return         returns s on success, and NULL on error or
 *                 when end of file occurs while no characters have been read.
 */
char * mbedtls_fgets( char *s, int size, mbedtls_file_t *stream )
{
    int status;
    size_t len = 0;

    mbedtls_serialize_push_int32( FILE_PTR_TO_INT( stream ) );
    mbedtls_serialize_push_int32( size );
    status = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FGETS );
    if ( status == 0 )
        mbedtls_serialize_pop_buffer( s, size, &len );
    return( s );
}

/**
 * \brief          Sets file position. Follows standard C fseek interface.
 *
 * \param stream   Pointer to mbedtls_file_t.
 * \param offset   Offset from whence.
 * \param whence   Position from where offset is applied.
 *                 Value is one of MBEDTLS_SEEK_SET, MBEDTLS_SEEK_CUR, or MBEDTLS_SEEK_END.
 *
 * \return         returns 0 on success, and -1 on error
 */
int mbedtls_fseek( mbedtls_file_t *stream, long offset, int whence )
{
    int status, ret = -1;

    switch( whence )
    {
        case MBEDTLS_SEEK_SET:
            whence = MBEDTLS_SERIALIZE_FSEEK_SET;
            break;
        case MBEDTLS_SEEK_CUR:
            whence = MBEDTLS_SERIALIZE_FSEEK_CUR;
            break;
        case MBEDTLS_SEEK_END:
            whence = MBEDTLS_SERIALIZE_FSEEK_END;
            break;
        default:
            return( -1 );
    }
    mbedtls_serialize_push_int32( FILE_PTR_TO_INT( stream ) );
    mbedtls_serialize_push_int32( whence );
    mbedtls_serialize_push_int32( offset );
    status = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FSEEK );
    if ( status == 0 )
        ret = 0;
    return( ret );
}

/**
 * \brief          Gives current position of file in bytes.
 *                 Follows standard C ftell interface.
 *
 * \param stream   Pointer to mbedtls_file_t.
 *
 * \return         returns current position on success, and -1 on error
 */
long mbedtls_ftell( mbedtls_file_t *stream )
{
    int status;
    uint32_t pos = 0;
    long ret = -1;

    mbedtls_serialize_push_int32( FILE_PTR_TO_INT( stream ) );
    status = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FTELL );
    if ( status == 0 )
    {
        mbedtls_serialize_pop_int32( &pos );
        ret = pos;
    }
    return( ret );
}

/**
 * \brief          Close file. Follows standard C fread interface.
 *
 * \param stream   Pointer to mbedtls_file_t.
 *
 * \return         Pointer to mbedtls_file_t on success or NULL on failure.
 */
int mbedtls_fclose( mbedtls_file_t *stream )
{
    int status, ret = -1;

    mbedtls_serialize_push_int32( FILE_PTR_TO_INT( stream ) );
    status = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FCLOSE );
    if ( status == 0 )
        ret = 0;
    return( ret );
}

/**
 * \brief          Test error indicator. Follows standard C ferror interface.
 *
 * \param stream   Pointer to mbedtls_file_t.
 *
 * \return         Non zero error code if error is set. 0 for no error.
 */
int mbedtls_ferror( mbedtls_file_t *stream )
{
    int status, ret = -1;

    mbedtls_serialize_push_int32( FILE_PTR_TO_INT( stream ) );
    status = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FERROR );
    if ( status == 0 )
        ret = 0;
    return( ret );
}

#endif /* MBEDTLS_SERIALIZE_C */
#endif /* else !MBEDTLS_FS_IO_ALT */
#endif /* MBEDTLS_FS_IO */
