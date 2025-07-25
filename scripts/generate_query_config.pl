#! /usr/bin/env perl

# Generate query_config.c
#
# The file query_config.c contains a C function that can be used to check if
# a configuration macro is defined and to retrieve its expansion in string
# form (if any). This facilitates querying the compile time configuration of
# the library, for example, for testing.
#
# The query_config.c is generated from the default configuration files
# include/mbedtls/mbedtls_config.h and include/psa/crypto_config.h.
# The idea is that mbedtls_config.h and crypto_config.h contain ALL the
# compile time configurations available in Mbed TLS (commented or uncommented).
# This script extracts the configuration macros from the two files and this
# information is used to automatically generate the body of the query_config()
# function by using the template in scripts/data_files/query_config.fmt.
#
# Usage: scripts/generate_query_config.pl without arguments, or
# generate_query_config.pl mbedtls_config_file psa_crypto_config_file template_file output_file
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

use strict;

my ($mbedtls_config_file, $psa_crypto_config_file, $query_config_format_file, $query_config_file);

my $default_mbedtls_config_file = "include/mbedtls/mbedtls_config.h";
my $default_psa_crypto_config_file = "tf-psa-crypto/include/psa/crypto_config.h";
my $default_query_config_format_file = "scripts/data_files/query_config.fmt";
my $default_query_config_file = "programs/test/query_config.c";

if( @ARGV ) {
    die "Invalid number of arguments - usage: $0 [MBED_TLS_CONFIG_FILE PSA_CRYPTO_CONFIG_FILE TEMPLATE_FILE OUTPUT_FILE]" if scalar @ARGV != 4;
    ($mbedtls_config_file, $psa_crypto_config_file, $query_config_format_file, $query_config_file) = @ARGV;

    -f $mbedtls_config_file or die "No such file: $mbedtls_config_file";
    -f $psa_crypto_config_file or die "No such file: $psa_crypto_config_file";
    -f $query_config_format_file or die "No such file: $query_config_format_file";
} else {
    $mbedtls_config_file = $default_mbedtls_config_file;
    $psa_crypto_config_file = $default_psa_crypto_config_file;
    $query_config_format_file = $default_query_config_format_file;
    $query_config_file = $default_query_config_file;

    unless(-f $mbedtls_config_file && -f $query_config_format_file  && -f $psa_crypto_config_file) {
        chdir '..' or die;
        -f $mbedtls_config_file && -f $query_config_format_file && -f $psa_crypto_config_file
          or die "No arguments supplied, must be run from project root or a first-level subdirectory\n";
    }
}
 -f 'include/mbedtls/build_info.h'
  or die "$0: must be run from project root, or from a first-level subdirectory with no arguments\n";

# Excluded macros from the generated query_config.c. For example, macros that
# have commas or function-like macros cannot be transformed into strings easily
# using the preprocessor, so they should be excluded or the preprocessor will
# throw errors.
my @excluded = qw(
MBEDTLS_SSL_CIPHERSUITES
);
my $excluded_re = join '|', @excluded;

# This variable will contain the string to replace in the CHECK_CONFIG of the
# format file
my $config_check = "";
my $list_config = "";

my %config_macro_names = ();

for my $config_file ($mbedtls_config_file, $psa_crypto_config_file) {

    next unless defined($config_file);  # we might not have been given a PSA crypto config file

    open(CONFIG_FILE, "<", $config_file) or die "Opening config file '$config_file': $!";

    while (my $line = <CONFIG_FILE>) {
        if ($line =~ /^(\/\/)?\s*#\s*define\s+(MBEDTLS_\w+|PSA_WANT_\w+).*/) {
            my $name = $2;

            # Skip over the macro if it is in the excluded list
            next if $name =~ /$excluded_re/;

            $config_macro_names{$name} = 1;

            $config_check .= <<EOT;
#if defined($name)
    if( strcmp( "$name", config ) == 0 )
    {
        MACRO_EXPANSION_TO_STR( $name );
        return( 0 );
    }
#endif /* $name */

EOT

            $list_config .= <<EOT;
#if defined($name)
    OUTPUT_MACRO_NAME_VALUE($name);
#endif /* $name */

EOT
        }
    }

    close(CONFIG_FILE);
}

# Read the full format file into a string
my $query_config_format = do {
    local $/;
    open(FORMAT_FILE, "<", $query_config_format_file)
      or die "Opening query config format file '$query_config_format_file': $!";
    my $query_config_format = <FORMAT_FILE>;
    close(FORMAT_FILE);
    $query_config_format
};

# Check that the format file includes all headers that might define
# config macros. This happens often to give a default value to
# macros with a name. It also happens with defined-or-not macros,
# although this is deprecated because it can cause a macro to seem to be
# undefined if it's used in an "#if defined(...)" check without having
# included the header that defines it.
my @headers_in_format = $query_config_format =~ m/^ *# *include *["<]([^"<>\n]+)[">]/mg;
my $headers_in_format_re = join('|', @headers_in_format);
my @all_public_header_files = glob('
    include/*/*.h
    include/*/*/*.h
    tf-psa-crypto/include/*/*.h
    tf-psa-crypto/include/*/*/*.h
    tf-psa-crypto/drivers/*/include/*/*.h
    tf-psa-crypto/drivers/*/include/*/*/*.h
');
my $errors = 0;
for my $header_file (@all_public_header_files) {
    my $header_path = $header_file;
    $header_path =~ s[(^|.*/)include/][];
    next if $header_path =~ m[
                              # Headers included by <PROJECT_NAME/build_info.h>
                              ^mbedtls/mbedtls_config\.h$ |
                              ^psa/crypto_config\.h$ |
                              [/_]adjust[_.] |
                              # Headers included directly by query_config.c
                              ^($headers_in_format_re)$
                             ]x;
    open HEADER_FILE, '<', $header_file or die;
    while (<HEADER_FILE>) {
        if (/^ *# *define +(\w+)/ && $config_macro_names{$1}) {
            print STDERR "$1 defined in $header_path which is not included\n";
            ++$errors;
        }
    }
    close HEADER_FILE;
}
exit 1 if $errors;

# Replace the body of the query_config() function with the code we just wrote
$query_config_format =~ s/CHECK_CONFIG/$config_check/g;
$query_config_format =~ s/LIST_CONFIG/$list_config/g;

# Rewrite the query_config.c file
open(QUERY_CONFIG_FILE, ">", $query_config_file) or die "Opening destination file '$query_config_file': $!";
print QUERY_CONFIG_FILE $query_config_format;
close(QUERY_CONFIG_FILE);
