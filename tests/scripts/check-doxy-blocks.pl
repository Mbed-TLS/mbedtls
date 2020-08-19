#!/usr/bin/env perl

# Detect comment blocks that are likely meant to be doxygen blocks but aren't.
#
# More precisely, look for normal comment block containing '\'.
# Of course one could use doxygen warnings, eg with:
#   sed -e '/EXTRACT/s/YES/NO/' doxygen/mbedtls.doxyfile | doxygen -
# but that would warn about any undocumented item, while our goal is to find
# items that are documented, but not marked as such by mistake.
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

use warnings;
use strict;
use File::Basename;

# C/header files in the following directories will be checked
my @directories = qw(include/mbedtls library doxygen/input);

# very naive pattern to find directives:
# everything with a backslach except '\0' and backslash at EOL
my $doxy_re = qr/\\(?!0|\n)/;

# Return an error code to the environment if a potential error in the
# source code is found.
my $exit_code = 0;

sub check_file {
    my ($fname) = @_;
    open my $fh, '<', $fname or die "Failed to open '$fname': $!\n";

    # first line of the last normal comment block,
    # or 0 if not in a normal comment block
    my $block_start = 0;
    while (my $line = <$fh>) {
        $block_start = $.   if $line =~ m/\/\*(?![*!])/;
        $block_start = 0    if $line =~ m/\*\//;
        if ($block_start and $line =~ m/$doxy_re/) {
            print "$fname:$block_start: directive on line $.\n";
            $block_start = 0; # report only one directive per block
            $exit_code = 1;
        }
    }

    close $fh;
}

sub check_dir {
    my ($dirname) = @_;
    for my $file (<$dirname/*.[ch]>) {
        check_file($file);
    }
}

# Check that the script is being run from the project's root directory.
for my $dir (@directories) {
    if (! -d $dir) {
        die "This script must be run from the mbed TLS root directory";
    } else {
        check_dir($dir)
    }
}

exit $exit_code;

__END__
