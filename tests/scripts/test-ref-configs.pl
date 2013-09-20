#!/usr/bin/perl

# test standard configurations:
# - build
# - run test suite
# - run compat.sh

use warnings;
use strict;

my %configs = (
    'config-psk-rc4-tls1_0.h'   => "-m tls1   -f 'PSK.*RC4'",
    'config-mini-tls1_1.h'
    => "-m tls1_1 -f '^DES-CBC3-SHA\$\|^TLS_RSA_WITH_3DES_EDE_CBC_SHA\$'",
    'config-suite-b.h'          => "-m tls1_2 -f 'ECDSA.*GCM'",
);

-d 'library' && -d 'include' && -d 'tests' or die "Must be run from root\n";

my $test = system( "grep -i cmake Makefile >/dev/null" ) ? 'check' : 'test';

my $config_h = 'include/polarssl/config.h';

system( "cp $config_h $config_h.bak" ) and die;
sub abort {
    system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
    die $_[0];
}

while( my ($conf, $args) = each %configs ) {
    system( "cp $config_h.bak $config_h" ) and die;
    system( "make clean" ) and die;

    print "\n******************************************\n";
    print "* Testing configuration: $conf\n";
    print "******************************************\n";

    system( "cd scripts && ./activate-config.pl data_files/$conf" )
        and abort "Failed to activate $conf\n";

    system( "make" ) and abort "Failed to build: $conf\n";
    system( "make $test" ) and abort "Failed test suite: $conf\n";
    system( "cd tests && ./compat.sh $args" )
        and abort "Failed compat.sh: $conf\n";
}

system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
system( "make clean" );
exit 0;
