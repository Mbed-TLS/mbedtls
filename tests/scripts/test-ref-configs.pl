#!/usr/bin/env perl

# test-ref-configs.pl
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
# For each reference configuration file in the configs directory, build the
# configuration, run the test suites and compat.sh
#
# Usage: tests/scripts/test-ref-configs.pl [config-name [...]]

use warnings;
use strict;

my %configs = (
    'config-ccm-psk-tls1_2.h' => {
        'compat' => '-m tls1_2 -f \'^TLS-PSK-WITH-AES-...-CCM-8\'',
    },
    'config-mini-tls1_1.h' => {
        'compat' => '-m tls1_1 -f \'^DES-CBC3-SHA$\|^TLS-RSA-WITH-3DES-EDE-CBC-SHA$\'',
    },
    'config-no-entropy.h' => {
    },
    'config-picocoin.h' => {
    },
    'config-suite-b.h' => {
        'compat' => "-m tls1_2 -f 'ECDHE-ECDSA.*AES.*GCM' -p mbedTLS",
    },
    'config-thread.h' => {
        'opt' => '-f ECJPAKE.*nolog',
    },
);

# If no config-name is provided, use all known configs.
# Otherwise, use the provided names only.
if ($#ARGV >= 0) {
    my %configs_ori = ( %configs );
    %configs = ();

    foreach my $conf_name (@ARGV) {
        if( ! exists $configs_ori{$conf_name} ) {
            die "Unknown configuration: $conf_name\n";
        } else {
            $configs{$conf_name} = $configs_ori{$conf_name};
        }
    }
}

-d 'library' && -d 'include' && -d 'tests' or die "Must be run from root\n";

my $config_h = 'include/mbedtls/config.h';

system( "cp $config_h $config_h.bak" ) and die;
sub abort {
    system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
    # use an exit code between 1 and 124 for git bisect (die returns 255)
    warn $_[0];
    exit 1;
}

while( my ($conf, $data) = each %configs ) {
    system( "cp $config_h.bak $config_h" ) and die;
    system( "make clean" ) and die;

    print "\n******************************************\n";
    print "* Testing configuration: $conf\n";
    print "******************************************\n";

    system( "cp configs/$conf $config_h" )
        and abort "Failed to activate $conf\n";

    system( "CFLAGS='-Os -Werror -Wall -Wextra' make" ) and abort "Failed to build: $conf\n";
    system( "make test" ) and abort "Failed test suite: $conf\n";

    my $compat = $data->{'compat'};
    if( $compat )
    {
        print "\nrunning compat.sh $compat\n";
        system( "tests/compat.sh $compat" )
            and abort "Failed compat.sh: $conf\n";
    }
    else
    {
        print "\nskipping compat.sh\n";
    }

    my $opt = $data->{'opt'};
    if( $opt )
    {
        print "\nrunning ssl-opt.sh $opt\n";
        system( "tests/ssl-opt.sh $opt" )
            and abort "Failed ssl-opt.sh: $conf\n";
    }
    else
    {
        print "\nskipping ssl-opt.sh\n";
    }
}

system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
system( "make clean" );
exit 0;
