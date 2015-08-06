/**
 * @file
 * TCP/IP communication module documentation file.
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @addtogroup tcpip_communication_module TCP/IP communication module
 *
 * The TCP/IP communication module provides for a channel of
 * communication for the \link ssltls_communication_module SSL/TLS communication
 * module\endlink to use.
 * In the TCP/IP-model it provides for communication up to the Transport
 * (or Host-to-host) layer.
 * SSL/TLS resides on top of that, in the Application layer, and makes use of
 * its basic provisions:
 * - listening on a port (see \c mbedtls_net_bind()).
 * - accepting a connection (through \c mbedtls_net_accept()).
 * - read/write (through \c mbedtls_net_recv()/\c mbedtls_net_send()).
 * - close a connection (through \c mbedtls_net_close()).
 *
 * This way you have the means to, for example, implement and use an UDP or
 * IPSec communication solution as a basis.
 *
 * This module can be used at server- and clientside to provide a basic
 * means of communication over the internet.
 */
