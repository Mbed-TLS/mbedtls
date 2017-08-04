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

#if !defined(MBEDTLS_FS_IO_ALT)
#include <stdio.h>
#include <dirent.h>

#define mbedtls_file_t      FILE
#define mbedtls_fread       fread
#define mbedtls_fgets       fgets
#define mbedtls_fwrite      fwrite
#define mbedtls_fclose      fclose
#define mbedtls_ferror      ferror
#define mbedtls_fseek       fseek
#define mbedtls_ftell       ftell
#define MBEDTLS_SEEK_SET    SEEK_SET
#define MBEDTLS_SEEK_CUR    SEEK_CUR
#define MBEDTLS_SEEK_END    SEEK_END

#define mbedtls_dir_t           DIR
#define MBEDTLS_FSIO_DT_BLK     DT_BLK
#define MBEDTLS_FSIO_DT_CHR     DT_CHR
#define MBEDTLS_FSIO_DT_DIR     DT_DIR
#define MBEDTLS_FSIO_DT_FIFO    DT_FIFO
#define MBEDTLS_FSIO_DT_LNK     DT_LNK
#define MBEDTLS_FSIO_DT_REG     DT_REG
#define MBEDTLS_FSIO_DT_SOCK    DT_SOCK
#define MBEDTLS_FSIO_DT_UNKNOWN DT_UNKNOWN

/**
 * \brief          Open file. Follows standard C fopen interface.
 *
 * \param path     File path
 * \param mode     Open mode
 *
 * \return         Pointer to mbedtls_file_t on success or NULL on failure.
 */
mbedtls_file_t * mbedtls_fopen( const char *path, const char *mode );
int mbedtls_readdir( mbedtls_dir_t * dir, char * file_name, int size,  int * type );

#else /* !MBEDTLS_FS_IO_ALT */

/**
 * file context.
 *
 */
typedef void mbedtls_file_t;

/**
 * dir context.
 *
 */
typedef void mbedtls_dir_t;

/**
 * Definition of whence required by mbedtls_fseek().
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
 * \brief          Open file. Follows standard C fopen interface.
 *
 * \param path     File path
 * \param mode     Open mode
 *
 * \return         Pointer to mbedtls_file_t on success or NULL on failure.
 */
mbedtls_file_t * mbedtls_fopen( const char *path, const char *mode );

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
                      mbedtls_file_t *stream );

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
                       mbedtls_file_t *stream );

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
char * mbedtls_fgets( char *s, int size, mbedtls_file_t *stream );

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
int mbedtls_fseek( mbedtls_file_t *stream, long offset, int whence );

/**
 * \brief          Gives current position of file in bytes.
 *                 Follows standard C ftell interface.
 *
 * \param stream   Pointer to mbedtls_file_t.
 *
 * \return         returns current position on success, and -1 on error
 */
long mbedtls_ftell( mbedtls_file_t *stream );

/**
 * \brief          Close file. Follows standard C fread interface.
 *
 * \param stream   Pointer to mbedtls_file_t.
 *
 * \return         Pointer to mbedtls_file_t on success or NULL on failure.
 */
int mbedtls_fclose( mbedtls_file_t *stream );

/**
 * \brief          Test error indicator. Follows standard C ferror interface.
 *
 * \param stream   Pointer to mbedtls_file_t.
 *
 * \return         Non zero error code if error is set. 0 for no error.
 */
int mbedtls_ferror( mbedtls_file_t *stream );


#endif /* !MBEDTLS_FS_IO_ALT */
#endif /* MBEDTLS_FS_IO */

#ifdef __cplusplus
}
#endif

#endif /* file.h */
