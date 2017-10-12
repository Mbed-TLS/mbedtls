/**
 * \file fsio.h
 *
 * \brief File read/write functions
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
#ifndef MBEDTLS_FILE_H
#define MBEDTLS_FILE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_FS_IO)
/* If MBEDTLS_FS_IO is enabled then file IO functions should be made available
 * via standard library or platform specific implementation. */

/* Default and alternative implementation specific interfaces. */
#if !defined(MBEDTLS_FS_IO_ALT)
#include <stdio.h>
#include <dirent.h>

typedef FILE *  mbedtls_file_t;
#define mbedtls_fread( buf, size, stream )      fread( buf, 1, size, stream )
#define mbedtls_fwrite( buf, size, stream )     fwrite( buf, 1, size, stream )
#define mbedtls_fgets       fgets
#define mbedtls_fclose      fclose
#define mbedtls_ferror      ferror
#define mbedtls_fseek       fseek
#define mbedtls_ftell       ftell
#define MBEDTLS_SEEK_SET    SEEK_SET
#define MBEDTLS_SEEK_CUR    SEEK_CUR
#define MBEDTLS_SEEK_END    SEEK_END
#define MBEDTLS_FILE_INVALID    NULL

typedef DIR *   mbedtls_dir_t;
#define mbedtls_opendir         opendir
#define mbedtls_closedir        closedir
#define MBEDTLS_FSIO_DT_BLK     DT_BLK
#define MBEDTLS_FSIO_DT_CHR     DT_CHR
#define MBEDTLS_FSIO_DT_DIR     DT_DIR
#define MBEDTLS_FSIO_DT_FIFO    DT_FIFO
#define MBEDTLS_FSIO_DT_LNK     DT_LNK
#define MBEDTLS_FSIO_DT_REG     DT_REG
#define MBEDTLS_FSIO_DT_SOCK    DT_SOCK
#define MBEDTLS_FSIO_DT_UNKNOWN DT_UNKNOWN
#define MBEDTLS_DIR_INVALID     NULL

#else /* !MBEDTLS_FS_IO_ALT */

/**
 * file handle.
 *
 */
typedef int32_t mbedtls_file_t;
#define MBEDTLS_FILE_INVALID    -1

/**
 * dir handle.
 *
 */
typedef int32_t mbedtls_dir_t;
#define MBEDTLS_DIR_INVALID     -1

/**
 * Definition of reference for seek offset used by mbedtls_fseek().
 */
#define MBEDTLS_SEEK_SET    0
#define MBEDTLS_SEEK_CUR    1
#define MBEDTLS_SEEK_END    2

/**
 * Definition of dir entry types required by mbedtls_readdir().
 */
#define MBEDTLS_FSIO_DT_BLK     0
#define MBEDTLS_FSIO_DT_CHR     1
#define MBEDTLS_FSIO_DT_DIR     2
#define MBEDTLS_FSIO_DT_FIFO    3
#define MBEDTLS_FSIO_DT_LNK     4
#define MBEDTLS_FSIO_DT_REG     5
#define MBEDTLS_FSIO_DT_SOCK    6
#define MBEDTLS_FSIO_DT_UNKNOWN 7

/**
 * \brief          Read file. Follows standard C fread interface.
 *
 * \param ptr      Pointer to output buffer
 * \param size     Size of output buffer.
 * \param stream   File handle (mbedtls_file_t).
 *
 * \return         Number of items read.
 */
size_t mbedtls_fread( void *ptr, size_t size, mbedtls_file_t stream );

/**
 * \brief          Write file. Follows standard C fwrite interface.
 *
 * \param ptr      Pointer to input buffer
 * \param size     Bytes to write.
 * \param stream   File handle of type mbedtls_file_t.
 *
 * \return         Number of items written.
 */
size_t mbedtls_fwrite( const void *ptr, size_t size, mbedtls_file_t stream );

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
char * mbedtls_fgets( char *s, int size, mbedtls_file_t stream );

/**
 * \brief          Sets file position. Follows standard C fseek interface.
 *
 * \param stream   File handle of type mbedtls_file_t.
 * \param offset   Offset from origin.
 * \param origin   Position from where offset is applied.
 *                 Value is one of MBEDTLS_SEEK_SET, MBEDTLS_SEEK_CUR, or MBEDTLS_SEEK_END.
 *
 * \return         returns 0 on success, and -1 on error
 */
int mbedtls_fseek( mbedtls_file_t stream, long offset, int origin );

/**
 * \brief          Gives current position of file in bytes.
 *                 Follows standard C ftell interface.
 *
 * \param stream   File handle of type mbedtls_file_t.
 *
 * \return         returns current position in bytes from the beginning of the
 *                 file. On error returns -1.
 */
long mbedtls_ftell( mbedtls_file_t stream );

/**
 * \brief          Close file. Follows standard C fread interface.
 *
 * \param stream   File handle of type mbedtls_file_t.
 *
 * \return         Pointer to mbedtls_file_t on success or NULL on failure.
 */
int mbedtls_fclose( mbedtls_file_t stream );

/**
 * \brief          Test error indicator. Follows standard C ferror interface.
 *
 * \param stream   File handle of type mbedtls_file_t.
 *
 * \return         Non zero error code if error is set. 0 for no error.
 */
int mbedtls_ferror( mbedtls_file_t stream );

/**
 * \brief          Open dir. Follows POSIX opendir interface.
 *
 * \param path     Path
 *
 * \return         Dir handle of type mbedtls_dir_t.
 *                 On failure MBEDTLS_DIR_INVALID is returned.
 */
mbedtls_dir_t mbedtls_opendir( const char *path );

#endif /* !MBEDTLS_FS_IO_ALT */

/* Common Interface prototypes */

/**
 * \brief          Open file. Follows standard C fopen interface.
 *
 * \param path     File path
 * \param mode     Open mode
 *
 * \return         File handle of type to mbedtls_file_t.
 *                 On failure MBEDTLS_FILE_INVALID is returned.
 */
mbedtls_file_t mbedtls_fopen( const char *path, const char *mode );

/**
 * \brief           Read dir entry (file, dir etc.).
 *
 * \param dir       File handle of type mbedtls_dir_t.
 * \param direntry  Out buffer for directory entry name.
 *                  Upto 255 character long name can be returned.
 * \param size      Out buffer length.
 * \param type      Entry type.
 *
 * \return          0 for success. Non zero for failure.
 */
int mbedtls_readdir( mbedtls_dir_t dir, char *direntry, uint32_t size,  uint32_t *type );

/**
 * \brief          Close dir. Follows POSIX closedir interface.
 *
 * \param dir      Dir handle of type mbedtls_dir_t.
 *
 * \return
 */
int mbedtls_closedir( mbedtls_dir_t dir );

#endif /* MBEDTLS_FS_IO */

#ifdef __cplusplus
}
#endif

#endif /* file.h */
