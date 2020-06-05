#!/usr/bin/env perl

# A simple TCP client that sends some data and expects a response.
# Usage: tcp_client.pl HOSTNAME PORT DATA1 RESPONSE1
#   DATA: hex-encoded data to send to the server
#   RESPONSE: regexp that must match the server's response
#
# Copyright (C) 2017, Arm Limited, All Rights Reserved
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# This file is provided under the Apache License 2.0, or the
# GNU General Public License v2.0 or later.
#
# **********
# Apache License 2.0:
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# **********
#
# **********
# GNU General Public License v2.0 or later:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# **********
#
# This file is part of Mbed TLS (https://tls.mbed.org)

use warnings;
use strict;
use IO::Socket::INET;

# Pack hex digits into a binary string, ignoring whitespace.
sub parse_hex {
    my ($hex) = @_;
    $hex =~ s/\s+//g;
    return pack('H*', $hex);
}

## Open a TCP connection to the specified host and port.
sub open_connection {
    my ($host, $port) = @_;
    my $socket = IO::Socket::INET->new(PeerAddr => $host,
                                       PeerPort => $port,
                                       Proto => 'tcp',
                                       Timeout => 1);
    die "Cannot connect to $host:$port: $!" unless $socket;
    return $socket;
}

## Close the TCP connection.
sub close_connection {
    my ($connection) = @_;
    $connection->shutdown(2);
    # Ignore shutdown failures (at least for now)
    return 1;
}

## Write the given data, expressed as hexadecimal
sub write_data {
    my ($connection, $hexdata) = @_;
    my $data = parse_hex($hexdata);
    my $total_sent = 0;
    while ($total_sent < length($data)) {
        my $sent = $connection->send($data, 0);
        if (!defined $sent) {
            die "Unable to send data: $!";
        }
        $total_sent += $sent;
    }
    return 1;
}

## Read a response and check it against an expected prefix
sub read_response {
    my ($connection, $expected_hex) = @_;
    my $expected_data = parse_hex($expected_hex);
    my $start_offset = 0;
    while ($start_offset < length($expected_data)) {
        my $actual_data;
        my $ok = $connection->recv($actual_data, length($expected_data));
        if (!defined $ok) {
            die "Unable to receive data: $!";
        }
        if (($actual_data ^ substr($expected_data, $start_offset)) =~ /[^\000]/) {
            printf STDERR ("Received \\x%02x instead of \\x%02x at offset %d\n",
                           ord(substr($actual_data, $-[0], 1)),
                           ord(substr($expected_data, $start_offset + $-[0], 1)),
                           $start_offset + $-[0]);
            return 0;
        }
        $start_offset += length($actual_data);
    }
    return 1;
}

if (@ARGV != 4) {
    print STDERR "Usage: $0 HOSTNAME PORT DATA1 RESPONSE1\n";
    exit(3);
}
my ($host, $port, $data1, $response1) = @ARGV;
my $connection = open_connection($host, $port);
write_data($connection, $data1);
if (!read_response($connection, $response1)) {
    exit(1);
}
close_connection($connection);
