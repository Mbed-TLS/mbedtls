#!/usr/bin/env perl
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

use strict;
use warnings;

if (!@ARGV || $ARGV[0] == '--help') {
    print <<EOF;
Usage: $0 mbedtls_test_foo <file.pem
       $0 TEST_FOO mbedtls_test_foo <file.pem
Print out a PEM file as C code defining a string constant.

Used to include some of the test data in /library/certs.c for
self-tests and sample programs.
EOF
    exit;
}

my $pp_name = @ARGV > 1 ? shift @ARGV : undef;
my $name = shift @ARGV;

my @lines = map {chomp; s/([\\"])/\\$1/g; "\"$_\\r\\n\""} <STDIN>;

if (defined $pp_name) {
    foreach ("#define $pp_name", @lines[0..@lines-2]) {
        printf "%-72s\\\n", $_;
    }
    print "$lines[@lines-1]\n";
    print "const char $name\[\] = $pp_name;\n";
} else {
    print "const char $name\[\] =";
    foreach (@lines) {
        print "\n$_";
    }
    print ";\n";
}
