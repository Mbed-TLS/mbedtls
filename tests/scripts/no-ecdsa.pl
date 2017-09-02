#!/usr/bin/perl

# no-ecdsa.pl
#
# Copyright (c) 2017, ARM Limited, All Rights Reserved
#
# Purpose
#
# To test the code dependencies on ecdsa build configuration. This is a
# verification step to ensure we don't ship test suites that do not work
# for some build options.
#
# Usage: no-ecdsa.pl
#
# This script should be executed from the root of the project directory.

use warnings;
use strict;

-d 'library' && -d 'include' && -d 'tests' or die "Must be run from root\n";

my $config_h = 'include/mbedtls/config.h';

system( "cp $config_h $config_h.bak" ) and die;
sub abort {
    system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
    die $_[0];
}

print "\n******************************************\n";
print "* Testing without MBEDTLS_ECDSA_C\n";
print "******************************************\n";

system( "scripts/config.pl unset MBEDTLS_ECDSA_C" )
    and abort "Failed to disable MBEDTLS_ECDSA_C\n";
# Disable also flag(s) with dependency on MBEDTLS_ECDSA_C.
system( "scripts/config.pl unset MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED" )
    and abort "Failed to disable MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED\n";

system( "make clean" ) and die;
system( "CFLAGS='-Werror -Wall -Wextra' make lib" )
    and abort "Failed to build lib without MBEDTLS_ECDSA_C\n";

system( "cd tests && make" )
    and abort "Failed to build tests without MBEDTLS_ECDSA_C\n";
system( "make test" )
    and abort "Failed test suite without MBEDTLS_ECDSA_C\n";

system( "mv $config_h.bak $config_h" ) and die "$config_h not restored\n";
system( "make clean" ) and die;
exit 0;
