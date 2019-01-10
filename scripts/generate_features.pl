#!/usr/bin/env perl

use strict;

# sources
my $config_h_file = 'include/mbedtls/config.h';
my $format_file = 'scripts/data_files/version_features.fmt';

# target
my $feature_file = 'include/mbedtls/version_features.h';

# make sure we're in the right directory
-r $config_h_file && -r $format_file or die "Must be run from root\n";

my @sections = ( "System support", "mbed TLS modules",
                 "mbed TLS feature support" );

my $line_separator = $/;
undef $/;

open(FORMAT_FILE, "$format_file") or die "Opening feature format file '$format_file': $!";
my $feature_format = <FORMAT_FILE>;
close(FORMAT_FILE);

$/ = $line_separator;

open(CONFIG_H, "$config_h_file") || die("Failure when opening config.h: $!");

my $feature_defines = "";
my $in_section = 0;

while (my $line = <CONFIG_H>)
{
    next if ($in_section && $line !~ /#define/ && $line !~ /SECTION/);
    next if (!$in_section && $line !~ /SECTION/);

    if ($in_section) {
        if ($line =~ /SECTION/) {
            $in_section = 0;
            next;
        }

        my ($define) = $line =~ /#define (\w+)/;
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

$feature_format =~ s/FEATURE_DEFINES\n/$feature_defines/g;

open(ERROR_FILE, ">$feature_file") or die "Opening destination file '$feature_file': $!";
print ERROR_FILE $feature_format;
close(ERROR_FILE);
