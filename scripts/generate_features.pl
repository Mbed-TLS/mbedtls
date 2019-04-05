#!/usr/bin/env perl
#

use strict;

my ($include_dir, $data_dir, $feature_file, $include_crypto);
my $crypto_include_dir = "crypto/include/mbedtls";

if( @ARGV ) {
    die "Invalid number of arguments" if scalar @ARGV != 4;
    ($include_dir, $data_dir, $feature_file, $include_crypto) = @ARGV;

    -d $include_dir or die "No such directory: $include_dir\n";
    -d $data_dir or die "No such directory: $data_dir\n";
    if( $include_crypto ) {
        -d $crypto_include_dir or die "Crypto submodule not present\n";
    }
} else {
    $include_dir = 'include/mbedtls';
    $data_dir = 'scripts/data_files';
    $feature_file = 'library/version_features.c';
    $include_crypto = 1;
    -d $crypto_include_dir or die "Crypto submodule not present\n";

    unless( -d $include_dir && -d $data_dir ) {
        chdir '..' or die;
        -d $include_dir && -d $data_dir
            or die "Without arguments, must be run from root or scripts\n"
    }
}

my $feature_format_file = $data_dir.'/version_features.fmt';

my @sections = ( "System support", "mbed TLS modules",
                 "mbed TLS feature support" );

my $line_separator = $/;
undef $/;

open(FORMAT_FILE, "$feature_format_file") or die "Opening feature format file '$feature_format_file': $!";
my $feature_format = <FORMAT_FILE>;
close(FORMAT_FILE);

$/ = $line_separator;
my %defines_seen;
my @files = ("$include_dir/config.h");

if( $include_crypto ) {
    push(@files, "$crypto_include_dir/config.h");
}

my $feature_defines = "";

foreach my $file (@files) {
    open(FILE, "$file") or die "Opening config file failed: '$file': $!";

    my $in_section = 0;

    while (my $line = <FILE>)
    {
        next if ($in_section && $line !~ /#define/ && $line !~ /SECTION/);
        next if (!$in_section && $line !~ /SECTION/);

        if ($in_section) {
            if ($line =~ /SECTION/) {
                $in_section = 0;
                next;
            }

            my ($define) = $line =~ /#define (\w+)/;

            # Skip if this define is already added
            if( $defines_seen{$define}++ ) {
                print "Skipping $define, already added. \n";
                next;
            }

            $feature_defines .= "#if defined(${define})\n";
            $feature_defines .= "    \"${define}\",\n";
            $feature_defines .= "#endif /* ${define} */\n";
        }

        if (!$in_section) {
            my ($section_name) = $line =~ /SECTION: ([\w ]+)/;
            my $found_section = grep $_ eq $section_name, @sections;

            $in_section = 1 if ($found_section);
        }
    };
    close(FILE);
}
$feature_format =~ s/FEATURE_DEFINES\n/$feature_defines/g;

open(ERROR_FILE, ">$feature_file") or die "Opening destination file '$feature_file': $!";
print ERROR_FILE $feature_format;
close(ERROR_FILE);
