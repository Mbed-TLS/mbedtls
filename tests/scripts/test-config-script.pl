#!/usr/bin/env perl
use warnings;
use strict;
use File::Basename;
use File::Copy;
use Getopt::Std;

sub detect_root {
    foreach my $dir ('.', '..', '../..',
                     dirname($0) . '/../..') {
        if (-d 'include/mbedtls' && -d 'scripts') {
            return $dir;
        }
    }
    die "Could not find the Mbed TLS root directory.\n";
}

sub detect_presets {
    my ($script) = @_;
    my @presets = ();
    foreach my $line (`$script 2>&1`) {
        if ($line =~ /^ +(\w(-|\w)*) + - /) {
            push @presets, $1;
        }
    }
    return @presets;
}

sub generate_configs {
    my ($script, $input_file, $output_directory, @presets) = @_;
    print STDERR "script=$script input=$input_file outdir=$output_directory presets=@presets\n";
    my $fh;
    foreach my $preset (@presets) {
        my $tmp_file = "$output_directory/config-$preset.tmp";
        my $output_file = "$output_directory/config-$preset.h";
        copy($input_file, $tmp_file)
          or die "copy($input_file, $tmp_file): $!";
        system($script, '-f', $tmp_file, $preset)
          and die "$script -f $tmp_file $preset: $?";
        rename($tmp_file, $output_file)
          or die "rename($tmp_file, $output_file): $!";
    }
}

$Getopt::Std::STANDARD_HELP_VERSION = 1;
sub HELP_MESSAGE {
    my ($fh, $package, $version, $switches) = @_;
    print $fh <<EOF
$0 [OPTION]... [PRESETS]
Run config.pl for PRESETS. With no positional arguments, automatically
detect the presets that config.pl supports.

This can be used to test changes in config.pl: compare the output of
this script before and after making the change.

  -c INPUT      Config file to process (default: include/mbedtls/config.h from root)
  -d DIR        Output directory (default: current directory)
  -r DIR        Root of the Mbed TLS tree (default: autodetect)
  -s SCRIPT     Script to run (default: scripts/config.pl from root)
EOF
}

sub main {
    my %options;
    getopts('c:d:r:s:', \%options) or exit(3);
    my $root = $options{r};
    if (!defined $root && !(exists $options{c} &&
                            exists $options{s})) {
        $root = detect_root();
    }
    my $input_file = $options{c};
    $input_file = "$root/include/mbedtls/config.h" if !defined $input_file;
    my $script = $options{s};
    $script = "$root/scripts/config.pl" if !defined $script;
    my $output_directory = $options{d};
    $output_directory = "." if !defined $output_directory;
    my @presets = @ARGV ? @ARGV : detect_presets($script);
    generate_configs($script, $input_file, $output_directory, @presets);
}

main;
