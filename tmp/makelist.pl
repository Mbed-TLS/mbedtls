#!/usr/bin/perl

use warnings;
use strict;

use utf8;
use open qw(:std utf8);

# build substitution table from a list of names on stdin or input files

my %special_cases = (
    'supported_ciphers' => 'mbedtls_cipher_supported',
    'f'                 => 'mbedtls_entropy_f',
    'source'            => 'mbedtls_entropy_source',
    'COLLECT'           => 'MBEDTLS_HAVEGE_COLLECT',
    'LN'                => 'MBEDTLS_MPI_LN',
    'key'               => 'mbedtls_ssl_key',
    'safer'             => 'mbedtls_ssl_safer',
    'alarmed'           => 'mbedtls_timing_alarmed',
    'get'               => 'mbedtls_timing_get',
    'hardclock'         => 'mbedtls_timing_hardclock',
    'hr'                => 'mbedtls_timing_hr',
    'm'                 => 'mbedtls_timing_m',
    'set'               => 'mbedtls_timing_set',
    'BADCERT'           => 'MBEDTLS_X509_BADCERT',
    'BADCRL'            => 'MBEDTLS_X509_BADCRL',
    'EXT'               => 'MBEDTLS_X509_EXT',
    'KU'                => 'MBEDTLS_X509_KU',
    'NS'                => 'MBEDTLS_X509_NS',
    't'                 => 'mbedtls_mpi',
);

my %subst;
while( my $name = <> ) {
    my $new;

    chomp $name;

    while( my ($prefix, $newpref) = each %special_cases ) {
        if( $name =~ /^$prefix($|_)/ ) {
            ($new = $name) =~ s/^$prefix/$newpref/;
            last;
        }
    }

    unless( $new ) {
        if( $name =~ /^POLARSSL_/ ) {
            ($new = $name) =~ s/POLARSSL/MBEDTLS/;
        } elsif( $name =~ /^polarssl_/ ) {
            ($new = $name) =~ s/polarssl/mbedtls/;
        } elsif( $name =~ /^_[a-z]/ ) {
            $new = "mbedtls$name";
        } elsif( $name =~ /^[A-Z]/ ) {
            $new = "MBEDTLS_$name";
        } elsif( $name =~ /^[a-z]/ ) {
            $new = "mbedtls_$name";
        } else {
            die "I don't know how to rename '$name'";
        }
    }

    $subst{$name} = $new;
}

printf "%s %s\n", $_, $subst{$_} for sort keys %subst;
