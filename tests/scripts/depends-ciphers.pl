#!/usr/bin/env perl

# depends-ciphers.pl
#
# Copyright (c) 2018, ARM Limited, All Rights Reserved
#
# Purpose
#
# To test the code dependencies on individual ciphers in each test suite. This
# is a verification step to ensure we don't ship test suites that do not work
# for some build options.
#
# The process is:
#       for each possible cipher
#           build the library and test suites with the hash disabled
#           execute the test suites
#
# And any test suite with the wrong dependencies will fail.
#
# Usage: tests/scripts/depends-ciphers.pl
#
# This script should be executed from the root of the project directory.
#
# For best effect, run either with cmake disabled, or cmake enabled in a mode
# that includes -Werror.

use warnings;
use strict;

-d 'library' && -d 'include' && -d 'tests' or die "Must be run from root\n";

my $config_h = 'include/mbedtls/config.h';

# get a list of ciphers from the cipher module
my $cipher_h = 'include/mbedtls/cipher.h';
my $sed_cmd = 's/^    MBEDTLS_CIPHER_ID_\([A-Z0-9_]*\),.*/\1/p';
my @ciphers = split( /\s+/, `sed -n -e '$sed_cmd' $cipher_h` );
@ciphers = map { "MBEDTLS_${_}_C" } grep { ! m/NULL|3DES/ } @ciphers;

# Some algorithms can't be disabled on their own as others depend on them, so
# we list those reverse-dependencies here to keep check_config.h happy.
my %revdeps = (
    'MBEDTLS_AES_C'         => ['MBEDTLS_CTR_DRBG_C', 'MBEDTLS_NIST_KW_C'],
);

system( "cp $config_h $config_h.bak" ) and die;
sub abort {
    system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
    # use an exit code between 1 and 124 for git bisect (die returns 255)
    warn $_[0];
    exit 1;
}

for my $cipher (@ciphers) {
    system( "cp $config_h.bak $config_h" ) and die "$config_h not restored\n";
    system( "make clean" ) and die;

    print "\n******************************************\n";
    print "* Testing without cipher: $cipher\n";
    print "******************************************\n";

    system( "scripts/config.pl full" )
        and abort "Failed to enable full config\n";
    # memory backtrace slows down tests too much
    system( "scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE" )
        and abort "Failed to disable MBEDTLS_MEMORY_BACKTRACE\n";

    system( "scripts/config.pl unset $cipher" )
        and abort "Failed to disable $cipher\n";
    if( exists $revdeps{$cipher} ) {
        for my $opt (@{ $revdeps{$cipher} }) {
            system( "scripts/config.pl unset $opt" )
                and abort "Failed to disable $opt\n";
        }
    }

    system( "CFLAGS='-Werror -O1' make" ) and abort "Failed to build: $cipher\n";
    system( "make test" ) and abort "Failed to run tests: $cipher\n";
}

system( "mv $config_h.bak $config_h" ) and die "$config_h not restored\n";
system( "make clean" ) and die;
exit 0;
