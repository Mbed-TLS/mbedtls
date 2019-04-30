#!/usr/bin/env perl

# test-ref-configs.pl
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2013-2016, ARM Limited, All Rights Reserved
#
# Purpose
#
# For each reference configuration file in the configs directory, build the
# configuration and run the test suites.
#
# Usage: tests/scripts/test-ref-configs.pl [config-name [...]]

use warnings;
use strict;

my %configs = (
    'config-suite-b.h' => {
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
}

system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
system( "make clean" );
exit 0;
