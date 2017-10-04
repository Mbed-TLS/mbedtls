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

#include <string.h>
#include <assert.h>
#include "mbedtls/fsio.h"

#if !defined(MBEDTLS_FS_IO_ALT)

#if !defined(MBEDTLS_PLATFORM_NO_STD_FUNCTIONS)
/**
 * \brief          Open file and disable buffering.
 *
 * \param path     File path
 * \param mode     Open mode
 *
 * \return         File handle of type mbedtls_file_t.
 *                 On failure MBEDTLS_FILE_INVALID is returned.
 */
mbedtls_file_t mbedtls_fopen( const char *path, const char *mode )
{
    mbedtls_file_t f = fopen( path, mode );

    if( f != MBEDTLS_FILE_INVALID && ( setvbuf( f, NULL, _IONBF, 0 ) != 0 ) )
    {
        fclose( f );
        f = MBEDTLS_FILE_INVALID;
    }

    return( f );
}

/**
 * \brief           Read next directory entry.
 *
 * \note            This is rework of readdir to adapt to abstraction. This does
 *                  not return struct dirent pointer. Hence no need to worry
 *                  pointer ownership and cleanup.
 *
 * \param dir       Dir handle of type mbedtls_dir_t.
 * \param file_name Out buffer for directory entry name.
 *                  Up to 255 character long name can be returned.
 * \param size      Out buffer length.
 * \param type      Out pointer entry type.
 *
 * \return          0 for success. -1 for failure.
 */
int mbedtls_readdir( mbedtls_dir_t dir, char *file_name, uint32_t size,  uint32_t *type )
{
    int status = -1;
    struct dirent *entry;

    if ( ( entry = readdir( dir ) ) != NULL )
    {
        strncpy( file_name, entry->d_name, size );
        if ( file_name[size - 1] == '\0' ) /* Check if buffer was enough */
        {
            *type = entry->d_type;
            status = 0;
        }
        else
        {
            file_name[0] = 0;
        }
    }

    return( status );
}

#endif /* !MBEDTLS_PLATFORM_NO_STD_FUNCTIONS */

#else /* !MBEDTLS_FS_IO_ALT */

#if defined(MBEDTLS_SERIALIZE_C)

#include "mbedtls/serialize.h"


/**
 * \brief           Check equality and return a specified value on failure.
 *                  It is a utility macro to check return status of a function
 *                  and return on error. Useful when there is a list of
 *                  functions to be called and each needs status check.
 *
 *                  Example: CHECK_STATUS( sum = add( 10, 5 ), 15, sum )
 *                      Above if add returns 15 control will fall through.
 *                      Else this macro will execute a return statement with sum.
 *
 * \param a,b       Values to check
 * \param r         Value to return when a != b
 */
#define CHECK_STATUS( a, b, r ) do { \
    if ( ( a ) != ( b ) ) \
        return( r );\
} while ( 0 )


/**
 * \brief          Open file. Follows standard C fopen interface.
 *
 * \param path     File path
 * \param mode     Open mode
 *
 * \return         File handle of type mbedtls_file_t.
 *                 On failure MBEDTLS_FILE_INVALID is returned.
 */
mbedtls_file_t mbedtls_fopen( const char *path, const char *mode )
{
    mbedtls_file_t file_id = MBEDTLS_FILE_INVALID;
    CHECK_STATUS( mbedtls_serialize_push_buffer( path, strlen( path ) + 1 ), 0, MBEDTLS_FILE_INVALID );
    CHECK_STATUS( mbedtls_serialize_push_buffer( mode, strlen( mode ) + 1 ), 0, MBEDTLS_FILE_INVALID );
    CHECK_STATUS( mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FOPEN ), 0, MBEDTLS_FILE_INVALID );
    CHECK_STATUS( mbedtls_serialize_pop_int32( ( uint32_t * )&file_id ), 0, MBEDTLS_FILE_INVALID );

    return( file_id );
}

/**
 * \brief          Read file. Follows standard C fread interface.
 *
 * \param ptr      Pointer to output buffer
 * \param size     Size of read items.
 * \param nmemb    Number of read items.
 * \param stream   File handle of type mbedtls_file_t.
 *
 * \return         Number of items read.
 */
size_t mbedtls_fread( void *ptr, size_t size, size_t nmemb,
                      mbedtls_file_t stream )
{
    size_t read = 0;

    /* Only byte size items allowed */
    if ( size != 1 )
        return( -1 );

    CHECK_STATUS( mbedtls_serialize_push_int32( stream ), 0, 0 );
    CHECK_STATUS( mbedtls_serialize_push_int32( nmemb ), 0, 0 );
    CHECK_STATUS( mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FREAD ), 0, 0 );
    CHECK_STATUS( mbedtls_serialize_pop_buffer( ptr, nmemb, &read ), 0, 0 );
    return( read );
}

/**
 * \brief          Write file. Follows standard C fwrite interface.
 *
 * \param ptr      Pointer to input buffer
 * \param size     Size of write items.
 * \param nmemb    Number of write items.
 * \param stream   File handle of type mbedtls_file_t.
 *
 * \return         Number of items written.
 */
size_t mbedtls_fwrite( const void *ptr, size_t size, size_t nmemb,
                       mbedtls_file_t stream )
{
    uint32_t written = 0;

    /* Only byte size items allowed */
    if ( size != 1 )
        return( -1 );

    CHECK_STATUS( mbedtls_serialize_push_int32( stream ), 0, 0 );
    CHECK_STATUS( mbedtls_serialize_push_buffer( ptr, nmemb ), 0, 0 );
    CHECK_STATUS( mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FWRITE ), 0, 0 );
    CHECK_STATUS( mbedtls_serialize_pop_int32( &written ), 0, 0 );
    return( written );
}

/**
 * \brief          Reads a line from file. Follows standard C fgets interface.
 *
 * \param s        Pointer to output buffer.
 * \param size     Size of buffer.
 * \param stream   File handle of type mbedtls_file_t.
 *
 * \return         returns s on success, and NULL on error or
 *                 when end of file occurs while no characters have been read.
 */
char * mbedtls_fgets( char *s, int size, mbedtls_file_t stream )
{
    size_t len = 0;

    CHECK_STATUS( mbedtls_serialize_push_int32( stream ), 0, NULL );
    CHECK_STATUS( mbedtls_serialize_push_int32( size ), 0, NULL );
    CHECK_STATUS( mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FGETS ), 0, NULL );
    CHECK_STATUS( mbedtls_serialize_pop_buffer( s, size, &len ), 0, NULL );
    return( s );
}

/**
 * \brief          Sets file position. Follows standard C fseek interface.
 *
 * \param stream   File handle of type mbedtls_file_t.
 * \param offset   Offset from whence.
 * \param whence   Position from where offset is applied.
 *                 Value is one of MBEDTLS_SEEK_SET, MBEDTLS_SEEK_CUR, or MBEDTLS_SEEK_END.
 *
 * \return         returns 0 on success, and -1 on error
 */
int mbedtls_fseek( mbedtls_file_t stream, long offset, int whence )
{
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
    CHECK_STATUS( mbedtls_serialize_push_int32( stream ), 0, -1 );
    CHECK_STATUS( mbedtls_serialize_push_int32( whence ), 0, -1 );
    CHECK_STATUS( mbedtls_serialize_push_int32( offset ), 0, -1 );
    CHECK_STATUS( mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FSEEK ), 0, -1 );
    return( 0 );
}

/**
 * \brief          Gives current position of file in bytes.
 *                 Follows standard C ftell interface.
 *
 * \param stream   File handle of type mbedtls_file_t.
 *
 * \return         returns current position on success, and -1 on error
 */
long mbedtls_ftell( mbedtls_file_t stream )
{
    long pos = 0;

    CHECK_STATUS( mbedtls_serialize_push_int32( stream ), 0, -1 );
    CHECK_STATUS( mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FTELL ), 0, -1 );
    CHECK_STATUS( mbedtls_serialize_pop_int32( (uint32_t *)&pos ), 0, -1 );
    return( pos );
}

/**
 * \brief          Close file. Follows standard C fread interface.
 *
 * \param stream   File handle of type mbedtls_file_t.
 *
 * \return         Pointer to mbedtls_file_t on success or NULL on failure.
 */
int mbedtls_fclose( mbedtls_file_t stream )
{
    CHECK_STATUS( mbedtls_serialize_push_int32( stream ), 0, -1 );
    CHECK_STATUS( mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FCLOSE ), 0, -1 );
    return( 0 );
}

/**
 * \brief          Test error indicator. Follows standard C ferror interface.
 *
 * \param stream   File handle of type mbedtls_file_t.
 *
 * \return         Non zero error code if error is set. 0 for no error.
 */
int mbedtls_ferror( mbedtls_file_t stream )
{
    int status;

    CHECK_STATUS( mbedtls_serialize_push_int32( stream ), 0, -1 );
    CHECK_STATUS( status = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_FERROR ), 0, status );
    return( 0 );
}

/**
 * \brief           Open dir. Follows POSIX opendir interface.
 *
 * \param path      Directory path string
 *
 * \return          Dir handle of type mbedtls_dir_t.
 *                  On failure MBEDTLS_DIR_INVALID is returned.
 */
mbedtls_dir_t mbedtls_opendir( const char * path )
{
    mbedtls_dir_t dir_id;

    CHECK_STATUS( mbedtls_serialize_push_buffer( path, strlen( path ) + 1 ), 0, MBEDTLS_DIR_INVALID );
    CHECK_STATUS( mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_DOPEN ), 0, MBEDTLS_DIR_INVALID );
    CHECK_STATUS( mbedtls_serialize_pop_int32( ( uint32_t * )&dir_id ), 0, MBEDTLS_DIR_INVALID );
    return( dir_id );
}

/**
 * \brief           Read dir entry (file, dir etc.).
 *
 * \param dir       Dir handle of type mbedtls_dir_t.
 * \param dirent    Out buffer for directory entry name.
 *                  Upto 255 character long name can be returned.
 * \param size      Out buffer length.
 * \param type      Entry type.
 *
 * \return          0 for success. Non zero for failure.
 */
int mbedtls_readdir( mbedtls_dir_t dir, char * dirent, uint32_t size,  uint32_t * type )
{
    size_t len = 0;

    CHECK_STATUS( mbedtls_serialize_push_int32( dir ), 0, -1 );
    CHECK_STATUS( mbedtls_serialize_push_int32( size ), 0, -1 );  /* Send entry size for validation */
    CHECK_STATUS( mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_DREAD ), 0, -1 );
    CHECK_STATUS( mbedtls_serialize_pop_int32( (uint32_t *)type ), 0, -1 );
    CHECK_STATUS( mbedtls_serialize_pop_buffer( dirent, size, &len ), 0, -1 );

    /* Map serialize dir entry type to fsio abstraction type */
    switch ( *type )
    {
        case MBEDTLS_SERIALIZE_DT_BLK:
            *type = MBEDTLS_FSIO_DT_BLK;
            break;
        case MBEDTLS_SERIALIZE_DT_CHR:
            *type = MBEDTLS_FSIO_DT_CHR;
            break;
        case MBEDTLS_SERIALIZE_DT_DIR:
            *type = MBEDTLS_FSIO_DT_DIR;
            break;
        case MBEDTLS_SERIALIZE_DT_FIFO:
            *type = MBEDTLS_FSIO_DT_FIFO;
            break;
        case MBEDTLS_SERIALIZE_DT_LNK:
            *type = MBEDTLS_FSIO_DT_LNK;
            break;
        case MBEDTLS_SERIALIZE_DT_REG:
            *type = MBEDTLS_FSIO_DT_REG;
            break;
        case MBEDTLS_SERIALIZE_DT_SOCK:
            *type = MBEDTLS_FSIO_DT_SOCK;
            break;
        case MBEDTLS_SERIALIZE_DT_UNKNOWN:
        default:
            *type = MBEDTLS_FSIO_DT_UNKNOWN;
            break;
    }
    return( 0 );
}

/**
 * \brief          Close dir. Follows posix closedir interface.
 *
 * \param dir      Dir handle of type mbedtls_dir_t.
 *
 * \return         0 on success, -1 on failure
 */
int mbedtls_closedir( mbedtls_dir_t dir )
{
    CHECK_STATUS( mbedtls_serialize_push_int32( dir ), 0, -1 );
    CHECK_STATUS( mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_DCLOSE ), 0, -1 );
    return( 0 );
}


#endif /* MBEDTLS_SERIALIZE_C */
#endif /* else !MBEDTLS_FS_IO_ALT */
#endif /* MBEDTLS_FS_IO */
