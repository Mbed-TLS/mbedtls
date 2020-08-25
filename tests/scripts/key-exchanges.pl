#!/usr/bin/env perl

# key-exchanges.pl
#
# Copyright The Mbed TLS Contributors
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
# Purpose
#
# To test the code dependencies on individual key exchanges in the SSL module.
# is a verification step to ensure we don't ship SSL code that do not work
# for some build options.
#
# The process is:
#       for each possible key exchange
#           build the library with all but that key exchange disabled
#
# Usage: tests/scripts/key-exchanges.pl
#
# This script should be executed from the root of the project directory.
#
# For best effect, run either with cmake disabled, or cmake enabled in a mode
# that includes -Werror.

use warnings;
use strict;

-d 'library' && -d 'include' && -d 'tests' or die "Must be run from root\n";

my $sed_cmd = 's/^#define \(MBEDTLS_KEY_EXCHANGE_.*_ENABLED\)/\1/p';
my $config_h = 'include/mbedtls/config.h';
my @kexes = split( /\s+/, `sed -n -e '$sed_cmd' $config_h` );

system( "cp $config_h $config_h.bak" ) and die;
sub abort {
    system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
    # use an exit code between 1 and 124 for git bisect (die returns 255)
    warn $_[0];
    exit 1;
}

for my $kex (@kexes) {
    system( "cp $config_h.bak $config_h" ) and die "$config_h not restored\n";
    system( "make clean" ) and die;

    print "\n******************************************\n";
    print "* Testing with key exchange: $kex\n";
    print "******************************************\n";

    # full config with all key exchanges disabled except one
    system( "scripts/config.pl full" ) and abort "Failed config full\n";
    for my $k (@kexes) {
        next if $k eq $kex;
        system( "scripts/config.pl unset $k" )
            and abort "Failed to disable $k\n";
    }

    system( "make lib CFLAGS='-Os -Werror'" ) and abort "Failed to build lib: $kex\n";
}

system( "mv $config_h.bak $config_h" ) and die "$config_h not restored\n";
system( "make clean" ) and die;
exit 0;
