#!/usr/bin/env perl

# run-test-suites.pl
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2015-2018, ARM Limited, All Rights Reserved
#
# Purpose
#
# Executes all the available test suites, and provides a basic summary of the
# results.
#
# Usage: run-test-suites.pl [-v] [--skip=SUITE,...]
#
# Options :
#   -v|--verbose    - Ignored for compatibility with other branches.
#   --skip=SUITE[,SUITE...]
#                   - Skip the specified SUITE(s). This option can be used
#                     multiple times.
#

use warnings;
use strict;

use Getopt::Long qw(:config gnu_compat);

use utf8;
use open qw(:std utf8);

# The --verbose option is recognized for compatibility with other branches,
# but it does nothing in Mbed TLS 2.1.
my $verbose;
my @skip_patterns;

GetOptions(
    'skip=s' => \@skip_patterns,
    'verbose|v' => \$verbose,
) or die "Command line option not recognized";

my @suites = grep { ! /\.(?:c|gcno)$/ } glob 'test_suite_*';
die "$0: no test suite found\n" unless @suites;

# "foo" as a skip pattern skips "test_suite_foo" and "test_suite_foo.bar"
# but not "test_suite_foobar".
my $skip_re =
    ( '\Atest_suite_(' .
      join('|', map {
          s/[ ,;]/|/g; # allow any of " ,;|" as separators
          s/\./\./g; # "." in the input means ".", not "any character"
          $_
      } @skip_patterns) .
      ')(\z|\.)' );

# in case test suites are linked dynamically
$ENV{'LD_LIBRARY_PATH'} = '../library';
$ENV{'DYLD_LIBRARY_PATH'} = '../library';

my $prefix = $^O eq "MSWin32" ? '' : './';

my ($failed_suites, $total_tests_run);
my $suites_skipped = 0;

for my $suite (@suites)
{
    print "$suite ", "." x ( 72 - length($suite) - 2 - 4 ), " ";

    if( $suite =~ /$skip_re/o ) {
        print "SKIP\n";
        ++$suites_skipped;
        next;
    }

    my $result = `$prefix$suite`;
    if( $result =~ /PASSED/ ) {
        print "PASS\n";
        my ($tests, $skipped) = $result =~ /([0-9]*) tests.*?([0-9]*) skipped/;
        $total_tests_run += $tests - $skipped;
    } else {
        $failed_suites++;
        print "FAIL\n";
    }
}

print "-" x 72, "\n";
print $failed_suites ? "FAILED" : "PASSED";
printf( " (%d suites, %d tests run%s)\n",
        scalar(@suites) - $suites_skipped,
        $total_tests_run,
        $suites_skipped ? ", $suites_skipped suites skipped" : "" );
exit( $failed_suites ? 1 : 0 );
