#!/usr/bin/perl
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2014-2016, ARM Limited, All Rights Reserved
#
# Purpose
#
# Comments and uncomments #define lines in the given header file and optionally
# sets their value or can get the value. This is to provide scripting control of
# what preprocessor symbols, and therefore what build time configuration flags
# are set in the 'config.h' file.
#
# Usage: config.pl [-f <file> | --file <file>] [-o | --force]
#                  { set <symbol> <value> | unset <symbol> | get <symbol> |
#                    full | realfull | baremetal |
#                    crypto_all }
#
# Full usage description provided below.
#
# Things that shouldn't be enabled with "full".
#
#   MBEDTLS_TEST_NULL_ENTROPY
#   MBEDTLS_DEPRECATED_REMOVED
#   MBEDTLS_HAVE_SSE2
#   MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#   MBEDTLS_ECP_DP_M221_ENABLED
#   MBEDTLS_ECP_DP_M383_ENABLED
#   MBEDTLS_ECP_DP_M511_ENABLED
#   MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
#   MBEDTLS_NO_PLATFORM_ENTROPY
#   MBEDTLS_REMOVE_ARC4_CIPHERSUITES
#   MBEDTLS_SSL_HW_RECORD_ACCEL
#   MBEDTLS_X509_ALLOW_EXTENSIONS_NON_V3
#   MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION
#       - this could be enabled if the respective tests were adapted
#   MBEDTLS_ZLIB_SUPPORT
#   MBEDTLS_PKCS11_C
#   and any symbol beginning _ALT
#

use warnings;
use strict;

my $config_file = "include/mbedtls/config.h";
my $usage = <<EOU;
$0 [-f <file> | --file <file>] [-o | --force]
                   [set <symbol> <value> | unset <symbol> | get <symbol> |
                        full | realfull | baremetal]

Commands
    set <symbol> [<value>]  - Uncomments or adds a #define for the <symbol> to
                              the configuration file, and optionally making it
                              of <value>.
                              If the symbol isn't present in the file an error
                              is returned.
    unset <symbol>          - Comments out the #define for the given symbol if
                              present in the configuration file.
    get <symbol>            - Finds the #define for the given symbol, returning
                              an exitcode of 0 if the symbol is found, and 1 if
                              not. The value of the symbol is output if one is
                              specified in the configuration file.
    full                    - Uncomments all #define's in the configuration file
                              excluding some reserved symbols, until the
                              'Module configuration options' section
    realfull                - Uncomments all #define's with no exclusions
    baremetal               - Sets full configuration suitable for baremetal build.
    crypto_all              - Enable all cryptography features including
                              deprecated or obsolescent algorithms. Disable
                              X.509, TLS and debugging.

Options
    -f | --file <filename>  - The file or file path for the configuration file
                              to edit. When omitted, the following default is
                              used:
                                $config_file
    -o | --force            - If the symbol isn't present in the configuration
                              file when setting its value, a #define is
                              appended to the end of the file.

EOU

my @excluded = qw(
MBEDTLS_TEST_NULL_ENTROPY
MBEDTLS_DEPRECATED_REMOVED
MBEDTLS_HAVE_SSE2
MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
MBEDTLS_ECP_DP_M221_ENABLED
MBEDTLS_ECP_DP_M383_ENABLED
MBEDTLS_ECP_DP_M511_ENABLED
MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
MBEDTLS_NO_PLATFORM_ENTROPY
MBEDTLS_REMOVE_ARC4_CIPHERSUITES
MBEDTLS_SSL_HW_RECORD_ACCEL
MBEDTLS_X509_ALLOW_EXTENSIONS_NON_V3
MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION
MBEDTLS_ZLIB_SUPPORT
MBEDTLS_PKCS11_C
MBEDTLS_NO_UDBL_DIVISION
\w+_ALT
);

# Things that should be disabled in "baremetal"
my @excluded_baremetal = qw(
MBEDTLS_NET_C
MBEDTLS_TIMING_C
MBEDTLS_FS_IO
MBEDTLS_ENTROPY_NV_SEED
MBEDTLS_HAVE_TIME
MBEDTLS_HAVE_TIME_DATE
MBEDTLS_DEPRECATED_WARNING
MBEDTLS_HAVEGE_C
MBEDTLS_THREADING_C
MBEDTLS_THREADING_PTHREAD
MBEDTLS_MEMORY_BACKTRACE
MBEDTLS_MEMORY_BUFFER_ALLOC_C
MBEDTLS_PLATFORM_TIME_ALT
MBEDTLS_PLATFORM_FPRINTF_ALT
);

# Things that should be excuded in non-full configurations
my @excluded_non_full = qw(
MBEDTLS_AES_ROM_TABLES
MBEDTLS_CAMELLIA_SMALL_MEMORY
MBEDTLS_DEPRECATED_\w+
MBEDTLS_ENTROPY_FORCE_SHA256
MBEDTLS_ENTROPY_NV_SEED
MBEDTLS_HAVEGE_C
MBEDTLS_MEMORY_\w+
MBEDTLS_PADLOCK_C
MBEDTLS_PLATFORM_\w+
MBEDTLS_RSA_NO_CRT
MBEDTLS_SHA256_SMALLER
MBEDTLS_THREADING_\w+
);

my @debug_features = qw(
MBEDTLS_DEBUG_C
MBEDTLS_MEMORY_\w+
);

my @x509_features = qw(
MBEDTLS_HAVE_TIME
MBEDTLS_HAVE_TIME_DATE
MBEDTLS_CERTS_C
MBEDTLS_X509_\w+
);

# Note that this includes all TLS features, including weak ciphersuites.
# Include all of these only for testing purposes, not in production.
my @tls_features = qw(
MBEDTLS_KEY_EXCHANGE_\w+
MBEDTLS_NET_C
MBEDTLS_TIMING_C
MBEDTLS_SSL_\w+
MBEDTLS_TLS_\w+
);

# Things that should be enabled in "full" even if they match @excluded
# These are all the platform ALT definitions, so that we test them in "full",
# except MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT which requires a platform_alt.h
# that we do not provide.
my @non_excluded = qw(
MBEDTLS_PLATFORM_(?!SETUP_TEARDOWN)\w+_ALT
);

# Things that should be enabled in "baremetal"
my @non_excluded_baremetal = qw(
MBEDTLS_NO_PLATFORM_ENTROPY
);

sub disjunction_re {
    return '^(?:' . join('|', @_) . ')$';
}
my $exclude_re = disjunction_re(@excluded);
my $exclude_non_full_re = disjunction_re(@excluded, @excluded_non_full);
my $no_exclude_re = disjunction_re(@non_excluded);
my $exclude_baremetal_re = disjunction_re(@excluded_baremetal);
my $no_exclude_baremetal_re = disjunction_re(@non_excluded_baremetal);
my $debug_features_re = disjunction_re(@debug_features);
my $x509_features_re = disjunction_re(@x509_features);
my $tls_features_re = disjunction_re(@tls_features);

my %presets = (
               baremetal => {exclude_re => qr/($exclude_re|$exclude_baremetal_re)/,
                             no_exclude_re => qr/(?!$exclude_baremetal_re)$no_exclude_re|$no_exclude_baremetal_re/},
               crypto_all => {exclude_re => qr/$exclude_non_full_re|$x509_features_re|$tls_features_re|$debug_features_re/,
                              no_exclude_re => qr/^$/},
               full => {exclude_re => qr/$exclude_re/,
                        no_exclude_re => qr/$no_exclude_re/},
               realfull => {exclude_re => qr/^$/,
                            no_exclude_re => qr/./},
              );

# Process the command line arguments

my $force_option = 0;

my ($arg, $name, $value, $action);

while ($arg = shift) {

    # Check if the argument is an option
    if ($arg eq "-f" || $arg eq "--file") {
        $config_file = shift;

        -f $config_file or die "No such file: $config_file\n";

    }
    elsif ($arg eq "-o" || $arg eq "--force") {
        $force_option = 1;

    }
    else
    {
        # ...else assume it's a command
        $action = $arg;

        if (exists $presets{$action}) {
            # No additional parameters
            die $usage if @ARGV;

        }
        elsif ($action eq "unset" || $action eq "get") {
            die $usage unless @ARGV;
            $name = shift;

        }
        elsif ($action eq "set") {
            die $usage unless @ARGV;
            $name = shift;
            $value = shift if @ARGV;

        }
        else {
            die "Command '$action' not recognised.\n\n".$usage;
        }
    }
}

# If no command was specified, exit...
if ( not defined($action) ){ die $usage; }

# Check the config file is present
if (! -f $config_file)  {

    chdir '..' or die;

    # Confirm this is the project root directory and try again
    if ( !(-d 'scripts' && -d 'include' && -d 'library' && -f $config_file) ) {
        die "If no file specified, must be run from the project root or scripts directory.\n";
    }
}


# Now read the file and process the contents

open my $config_read, '<', $config_file or die "read $config_file: $!\n";
my @config_lines = <$config_read>;
close $config_read;

my $config_write = undef;
if ($action ne "get") {
    open $config_write, '>', $config_file or die "write $config_file: $!\n";
}

my $done;
for my $line (@config_lines) {
    if (exists $presets{$action}) {
        my %settings = %{$presets{$action}};
        if ($line =~ /name SECTION: Module configuration options/) {
            $done = 1;
        }

        if (!$done && $line =~ m!^(//)?\s?#define\s+(\w+)!) {
            my $disabled = !!$1;
            my $option = $2;
            if ($disabled && ($option !~ /$settings{exclude_re}/ ||
                              $option =~ /$settings{no_exclude_re}/)) {
                $line =~ s!^//\s?!!;
            }
            if (!$disabled && !($option !~ /$settings{exclude_re}/ ||
                                $option =~ /$settings{no_exclude_re}/)) {
                $line =~ s!^!//!;
            }
       }
    } elsif ($action eq "unset") {
        if (!$done && $line =~ /^\s*#define\s*$name\b/) {
            $line = '//' . $line;
            $done = 1;
        }
    } elsif (!$done && $action eq "set") {
        if ($line =~ m!^(?://)?\s*#define\s*$name\b!) {
            $line = "#define $name";
            $line .= " $value" if defined $value && $value ne "";
            $line .= "\n";
            $done = 1;
        }
    } elsif (!$done && $action eq "get") {
        if ($line =~ /^\s*#define\s*$name(?:\s+(.*?))\s*(?:$|\/\*|\/\/)/) {
            $value = $1;
            $done = 1;
        }
    }

    if (defined $config_write) {
        print $config_write $line or die "write $config_file: $!\n";
    }
}

# Did the set command work?
if ($action eq "set" && $force_option && !$done) {

    # If the force option was set, append the symbol to the end of the file
    my $line = "#define $name";
    $line .= " $value" if defined $value && $value ne "";
    $line .= "\n";
    $done = 1;

    print $config_write $line or die "write $config_file: $!\n";
}

if (defined $config_write) {
    close $config_write or die "close $config_file: $!\n";
}

if ($action eq "get") {
    if ($done) {
        if ($value ne '') {
            print "$value\n";
        }
        exit 0;
    } else {
        # If the symbol was not found, return an error
        exit 1;
    }
}

if ($action eq "full" && !$done) {
    die "Configuration section was not found in $config_file\n";

}

if ($action ne "full" && $action ne "unset" && !$done) {
    die "A #define for the symbol $name was not found in $config_file\n";
}

__END__
