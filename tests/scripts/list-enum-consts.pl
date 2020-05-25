#!/usr/bin/env perl
#
# Copyright (C) 2015, Arm Limited, All Rights Reserved
# SPDX-License-Identifier: Apache-2.0
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
# This file is part of Mbed TLS (https://tls.mbed.org)

use warnings;
use strict;

use utf8;
use open qw(:std utf8);

-d 'include/mbedtls' or die "$0: must be run from root\n";

@ARGV = grep { ! /compat-1\.3\.h/ } <include/mbedtls/*.h>;

my @consts;
my $state = 'out';
while (<>)
{
    if( $state eq 'out' and /^(typedef )?enum \{/ ) {
        $state = 'in';
    } elsif( $state eq 'out' and /^(typedef )?enum/ ) {
        $state = 'start';
    } elsif( $state eq 'start' and /{/ ) {
        $state = 'in';
    } elsif( $state eq 'in' and /}/ ) {
        $state = 'out';
    } elsif( $state eq 'in' ) {
        s/=.*//; s!/\*.*!!; s/,.*//; s/\s+//g; chomp;
        push @consts, $_ if $_;
    }
}

open my $fh, '>', 'enum-consts' or die;
print $fh "$_\n" for sort @consts;
close $fh or die;

printf "%8d enum-consts\n", scalar @consts;
