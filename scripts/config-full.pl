#!/usr/bin/perl

use warnings;
use strict;

# Things that shouldn't be enabled.
# Notes:
# - POLARSSL_X509_ALLOW_EXTENSIONS_NON_V3 and
#   POLARSSL_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION could be enabled if the
#   respective tests were adapted
my @excluded = qw(
POLARSSL_HAVE_INT8
POLARSSL_HAVE_INT16
POLARSSL_HAVE_SSE2
POLARSSL_PLATFORM_NO_STD_FUNCTIONS
POLARSSL_ECP_DP_M221_ENABLED
POLARSSL_ECP_DP_M383_ENABLED
POLARSSL_ECP_DP_M511_ENABLED
POLARSSL_NO_DEFAULT_ENTROPY_SOURCES
POLARSSL_NO_PLATFORM_ENTROPY
POLARSSL_SSL_HW_RECORD_ACCEL
POLARSSL_X509_ALLOW_EXTENSIONS_NON_V3
POLARSSL_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION
POLARSSL_ZLIB_SUPPORT
POLARSSL_PKCS11_C
_ALT\s*$
);

my $include_dir;

if( @ARGV ) {
    die "Invalid number of arguments" if scalar @ARGV != 1;
    ($include_dir) = @ARGV;

    -d $include_dir or die "No such directory: $include_dir\n";
} else {
    $include_dir = 'include/polarssl';

    unless( -d $include_dir ) {
        chdir '..' or die;
        -d $include_dir
            or die "Without arguments, must be run from root or scripts\n"
    }
}

my $config_file = "$include_dir/config.h";

open my $config_read, '<', $config_file or die "read $config_file: $!\n";
my @config_lines = <$config_read>;
close $config_read;

my $exclude_re = join '|', @excluded;

open my $config_write, '>', $config_file or die "write $config_file: $!\n";

my $done;
for my $line (@config_lines) {
    if ($line =~ /name SECTION: Module configuration options/) {
        $done = 1;
    }

    if (!$done && $line =~ m!^//\s?#define! && $line !~ /$exclude_re/) {
        $line =~ s!^//!!;
    }

    print $config_write $line;
}

close $config_write;

__END__
