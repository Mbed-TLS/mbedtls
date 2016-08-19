#!/usr/bin/env perl

# generate_code.pl
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2009-2016, ARM Limited, All Rights Reserved
#
# Purpose
#
# Generates the test suite code given inputs of the test suite directory that
# contain the test suites, and the test suite file names for the test code and
# test data.
#
# It is also possible to generate test code for on target testing in mbed 5.0
# by passing the --mbed flag as a command line argument to this script. In this
# case, C++ files will be generated (instead of C files). To use the generated
# source code, clone the repository at git@github.com:ARMmbed/mbed-os.git.
# Then copy all the .cpp files into appropriate directories under
# mbed-os/TESTS. This can be easily achieved using bash commands such as:
#     mkdir <MBED_OS_ROOT>/TESTS/mbedtls
#     for suite in test_suite_*.cpp; do
#         mkdir <MBED_OS_ROOT>/TESTS/mbedtls/${suite%.cpp}
#         cp $suite <MBED_OS_ROOT>/TESTS/mbedtls/${suite%.cpp}/.
#     done
# Then compile the tests using mbed-cli and ensure that there are no errors:
#     cd <MBED_OS_ROOT>
#     mbed test --compile -m K64F -t GCC_ARM --test-spec test_spec.json
# Finally, run the tests using mbedgt:
#     mbedgt -VS --test-spec test_spec.json
# Notes:
#   - To successfully run the mbed 5.0 tests, make sure that you have the
#     necessary hardware e.g. K64F.
#   - Ensure that the necessary software tools are available in your
#     environment: mbed-cli, mbed greeentea (mbedgt), htrun, mbed-ls.
#   - On Linux systems, you may need to add your user to the dialout Unix
#     group; otherwise, mbedgt may not be able to connect to the hardware
#     target using the serial interface. Alternatively, run mbedgt using sudo.
#
# Structure of files
#
#   - main code file - 'main_test.function'
#       Template file that contains the main() function for the test suite,
#       test dispatch code as well as support functions. It contains the
#       following symbols which are substituted by this script during
#       processing:
#           TESTCASE_FILENAME
#           TESTCODE_FILENAME
#           SUITE_PRE_DEP
#           MAPPING_CODE
#           FUNCTION CODE
#           SUITE_POST_DEP
#           DEP_CHECK_CODE
#           DISPATCH_FUNCTION
#           !LINE_NO!
#           TEST_DATA_CODE
#           TEST_ASSERT
#
#   - common helper code file - 'helpers.function'
#       Common helper functions
#
#   - test suite code file - file name in the form 'test_suite_xxx.function'
#       Code file that contains the actual test cases. The file contains a
#       series of code sequences delimited by the following:
#           BEGIN_HEADER / END_HEADER - list of headers files
#           BEGIN_SUITE_HELPERS / END_SUITE_HELPERS - helper functions common to
#               the test suite
#           BEGIN_CASE / END_CASE - the test cases in the test suite. Each test
#               case contains at least one function that is used to create the
#               dispatch code.
#
#   - test data file - file name in the form 'test_suite_xxxx.data'
#       The test case parameters to to be used in execution of the test. The
#       file name is used to replace the symbol 'TESTCASE_FILENAME' in the main
#       code file above.
#

use strict;
use Getopt::Long;

#
# Helper functions
#

sub usage {
    print "Error while parsing command line arguments.\n";
    print "This script generates test code for mbed TLS.\n";
    print "USAGE:\n";
    print "\t--suitedir\t\tSuite directory\n";
    print "\t--suitename\t\tSuite name\n";
    print "\t--dataname\t\tName of data file\n";
    print "\t--mainfile\t\tFile containing the code for main functions\n";
    print "\t--mbed\t\tWhether this test is for the mbed platform\n";
    exit 1;
}

sub write_test_suite_src {
    my $filename = shift;
    my $src = shift;
    open(TEST_FILE, ">$filename") or die "Opening destination file '$filename': $!";
    print TEST_FILE << "END";
$src
END
    close(TEST_FILE);
}

#
# Parse command line arguments
#

my $suite_dir = "";
my $suite_name = "";
my $data_name = "";
my $test_main_file = "";
my $is_mbed = 0;

GetOptions("suitedir=s" => \$suite_dir,
           "suitename=s" => \$suite_name,
           "dataname=s" => \$data_name,
           "mainfile=s" => \$test_main_file,
           "mbed" => \$is_mbed) or usage();

$suite_dir ne "" or die "Missing suite directory";
$suite_name ne "" or die "Missing suite name";
$data_name ne "" or die "Missing data name";
$test_main_file = $suite_dir."/main_test.function" if ($test_main_file eq "");

# mbed files can only be c++
my $test_file = $is_mbed ? $data_name.".cpp" : $data_name.".c";
my $test_common_helper_file = $suite_dir."/helpers.function";
my $test_case_file = $suite_dir."/".$suite_name.".function";
my $test_case_data = $suite_dir."/".$data_name.".data";

my $line_separator = $/;
undef $/;

#
# Open and read in the input files
#

open(TEST_HELPERS, "$test_common_helper_file") or die "Opening test helpers
'$test_common_helper_file': $!";
my $test_common_helpers = <TEST_HELPERS>;
if ($is_mbed)
{
    $test_common_helpers =~ s/TEST_ASSERT/MBEDTLS_TEST_ASSERT/;
}
close(TEST_HELPERS);

open(TEST_MAIN, "$test_main_file") or die "Opening test main '$test_main_file': $!";
my @test_main_lines = split/^/,  <TEST_MAIN>;
my $test_main;
my $index = 2;
for my $line (@test_main_lines) {
    $line =~ s/!LINE_NO!/$index/;
    $test_main = $test_main.$line;
    $index++;
}
close(TEST_MAIN);

open(TEST_CASES, "$test_case_file") or die "Opening test cases '$test_case_file': $!";
my @test_cases_lines = split/^/,  <TEST_CASES>;
my $test_cases;
my $index = 2;
for my $line (@test_cases_lines) {
    if ($line =~ /^\/\* BEGIN_SUITE_HELPERS .*\*\//)
    {
        $line = $line."#line $index \"$test_case_file\"\n";
    }

    if ($line =~ /^\/\* BEGIN_CASE .*\*\//)
    {
        $line = $line."#line $index \"$test_case_file\"\n";
    }

    $line =~ s/!LINE_NO!/$index/;

    $test_cases = $test_cases.$line;
    $index++;
}
if ($is_mbed)
{
    $test_cases =~ s/TEST_ASSERT/MBEDTLS_TEST_ASSERT/g;
}

close(TEST_CASES);

open(TEST_DATA, "$test_case_data") or die "Opening test data '$test_case_data': $!";
my $test_data = <TEST_DATA>;

# Divide source data in 100KB chunks
my @test_data_chunks = ();
# Chunk size in bytes (characters)
my $max_chunk_size = 102400;
my $chunk_index = 0;

# Tests that are meant for running on an MCU cannot read files. Therefore,
# we encode the test suite .data files inside the test suite C++ source code.
# Nevertheless, some MCU have really tight constraints on FLASH memory, so
# it is necessary to split the test suite into multiple source files that can
# be run independently. The code below takes care of correctly formatting and
# escaping the test suite data, also it splits the data into source code
# chunks that are roughly $max_chunk_size bytes.
if ($is_mbed)
{
    my @test_data_lines = split/^/, $test_data;
    for my $line (@test_data_lines) {
        chop($line);
        # Escape any \ in the input data
        $line =~ s/\\/\\\\/g;
        # Escape " character
        $line =~ s/"/\\"/g;

        # If this is the end of a test case, then test whether the maximum
        # data size for the test has been overflowed and split the test
        # accordingly
        if ($line eq "")
        {
            # Check if we need to make a new chunk
            if (length($test_data_chunks[$chunk_index]) >= $max_chunk_size)
            {
                # Properly terminate the current test
                $test_data_chunks[$chunk_index] .= "\"";
                push(@test_data_chunks, "");
                $chunk_index++;
            }
            else
            {
                # There is free space in the current chunk
                if ($test_data_chunks[$chunk_index] eq "")
                {
                    $line = "\"".$line;
                }
                else
                {
                    $line = "\\n\"\n        \"".$line;
                }
                $test_data_chunks[$chunk_index] .= $line;
            }
        }
        else
        {
            if ($test_data_chunks[$chunk_index] eq "")
            {
                $line = "\"".$line;
            }
            else
            {
                $line = "\\n\"\n        \"".$line;
            }
            $test_data_chunks[$chunk_index] .= $line;
        }
    }
    if ($test_data_chunks[$chunk_index] eq "")
    {
        # If there is an additional new line at the end of the data file, then
        # it is possible that we have a trailing empty chunk, remove that.
        pop(@test_data_chunks);
    }
    else
    {
        # If there is no trailing empty chunk, then we have not properly closed
        # the " in the last chunk
        $test_data_chunks[$chunk_index] .= "\"";
    }
}
close(TEST_DATA);

#
# Find the headers, dependencies, and suites in the test cases file
#

my ( $suite_header ) = $test_cases =~ /\/\* BEGIN_HEADER \*\/\n(.*?)\n\/\* END_HEADER \*\//s;
my ( $suite_defines ) = $test_cases =~ /\/\* BEGIN_DEPENDENCIES\n \* (.*?)\n \* END_DEPENDENCIES/s;
my ( $suite_helpers ) = $test_cases =~ /\/\* BEGIN_SUITE_HELPERS \*\/\n(.*?)\n\/\* END_SUITE_HELPERS \*\//s;

my $requirements;
if ($suite_defines =~ /^depends_on:/)
{
    ( $requirements ) = $suite_defines =~ /^depends_on:(.*)$/;
}

my @var_req_arr = split(/:/, $requirements);
my $suite_pre_code;
my $suite_post_code;
my $dispatch_code;
my $mapping_code;
my %mapping_values;

while (@var_req_arr)
{
    my $req = shift @var_req_arr;
    $req =~ s/(!?)(.*)/$1defined($2)/;

    $suite_pre_code .= "#if $req\n";
    $suite_post_code .= "#endif /* $req */\n";
}

$/ = $line_separator;

# Add any other header file inclusions
my $test_headers = "";
if ($is_mbed)
{
    $test_headers .= << "END";
#include "mbed.h"
#include "greentea-client/test_env.h"
#include "unity.h"
#include "utest.h"
#include "rtos.h"

using namespace utest::v1;
END
}

my $test_src = << "END";
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script: $0
 *
 * Test file      : $test_file
 *
 * The following files were used to create this file.
 *
 *      Main code file  : $test_main_file
 *      Helper file     : $test_common_helper_file
 *      Test suite file : $test_case_file
 *      Test suite data : $test_case_data
 *
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

$test_headers

/*----------------------------------------------------------------------------*/
/* Common helper code */

$test_common_helpers


/*----------------------------------------------------------------------------*/
/* Test Suite Code */

$suite_pre_code
$suite_header
$suite_helpers
$suite_post_code

END

$test_main =~ s/SUITE_PRE_DEP/$suite_pre_code/;
$test_main =~ s/SUITE_POST_DEP/$suite_post_code/;

while($test_cases =~ /\/\* BEGIN_CASE *([\w:]*) \*\/\n(.*?)\n\/\* END_CASE \*\//msg)
{
    my $function_deps = $1;
    my $function_decl = $2;

    # Sanity checks of function
    if ($function_decl !~ /^#line\s*.*\nvoid /)
    {
        die "Test function does not have 'void' as return type.\n" .
            "Function declaration:\n" .
            $function_decl;
    }
    if ($function_decl !~ /^(#line\s*.*)\nvoid (\w+)\(\s*(.*?)\s*\)\s*{(.*)}/ms)
    {
        die "Function declaration not in expected format\n";
    }
    my $line_directive = $1;
    my $function_name = $2;
    my $function_params = $3;
    my $function_pre_code;
    my $function_post_code;
    my $param_defs;
    my $param_checks;
    my @dispatch_params;
    my @var_def_arr = split(/,\s*/, $function_params);
    my $i = 1;
    my $mapping_regex = "".$function_name;
    my $mapping_count = 0;

    $function_decl =~ s/(^#line\s*.*)\nvoid /$1\nvoid test_suite_/;

    # Add exit label if not present
    if ($function_decl !~ /^exit:$/m)
    {
        $function_decl =~ s/}\s*$/\nexit:\n    return;\n}/;
    }

    if ($function_deps =~ /^depends_on:/)
    {
        ( $function_deps ) = $function_deps =~ /^depends_on:(.*)$/;
    }

    foreach my $req (split(/:/, $function_deps))
    {
        $function_pre_code .= "#ifdef $req\n";
        $function_post_code .= "#endif /* $req */\n";
    }

    foreach my $def (@var_def_arr)
    {
        # Handle the different parameter types
        if( substr($def, 0, 4) eq "int " )
        {
            $param_defs .= "    int param$i;\n";
            $param_checks .= "    if( verify_int( params[$i], &param$i ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );\n";
            push @dispatch_params, "param$i";

            $mapping_regex .= ":([\\d\\w |\\+\\-\\(\\)]+)";
            $mapping_count++;
        }
        elsif( substr($def, 0, 6) eq "char *" )
        {
            $param_defs .= "    char *param$i = params[$i];\n";
            $param_checks .= "    if( verify_string( &param$i ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );\n";
            push @dispatch_params, "param$i";
            $mapping_regex .= ":[^:\n]+";
        }
        else
        {
            die "Parameter declaration not of supported type (int, char *)\n";
        }
        $i++;

    }

    # Find non-integer values we should map for this function
    if( $mapping_count)
    {
        my @res = $test_data =~ /^$mapping_regex/msg;
        foreach my $value (@res)
        {
            next unless ($value !~ /^\d+$/);
            if ( $mapping_values{$value} ) {
                ${ $mapping_values{$value} }{$function_pre_code} = 1;
            } else {
                $mapping_values{$value} = { $function_pre_code => 1 };
            }
        }
    }

    my $call_params = join ", ", @dispatch_params;
    my $param_count = @var_def_arr + 1;
    $dispatch_code .= << "END";
if( strcmp( params[0], "$function_name" ) == 0 )
{
$function_pre_code
$param_defs
    if( cnt != $param_count )
    {
        mbedtls_fprintf( stderr, "\\nIncorrect argument count (%d != %d)\\n", cnt, $param_count );
        return( DISPATCH_INVALID_TEST_DATA );
    }

$param_checks
    test_suite_$function_name( $call_params );
    return ( DISPATCH_TEST_SUCCESS );
$function_post_code
    return ( DISPATCH_UNSUPPORTED_SUITE );
}
else
END

    my $function_code = $function_pre_code . $function_decl . "\n" .
                        $function_post_code;
    $test_main =~ s/FUNCTION_CODE/$function_code\nFUNCTION_CODE/;
}

# Find specific case dependencies that we should be able to check
# and make check code
my $dep_check_code;

my @res = $test_data =~ /^depends_on:([\w:]+)/msg;
my %case_deps;
foreach my $deps (@res)
{
    foreach my $dep (split(/:/, $deps))
    {
        $case_deps{$dep} = 1;
    }
}
while( my ($key, $value) = each(%case_deps) )
{
    $dep_check_code .= << "END";
    if( strcmp( str, "$key" ) == 0 )
    {
#if defined($key)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
END
}

# Make mapping code
while( my ($key, $value) = each(%mapping_values) )
{
    my $key_mapping_code = << "END";
    if( strcmp( str, "$key" ) == 0 )
    {
        *value = ( $key );
        return( KEY_VALUE_MAPPING_FOUND );
    }
END

    # handle depenencies, unless used at least one without depends
    if ($value->{""}) {
        $mapping_code .= $key_mapping_code;
        next;
    }
    for my $ifdef ( keys %$value ) {
        (my $endif = $ifdef) =~ s!ifdef!endif //!g;
        $mapping_code .= $ifdef . $key_mapping_code . $endif;
    }
}

$dispatch_code =~ s/^(.+)/    $1/mg;

$test_main =~ s/TESTCASE_FILENAME/$test_case_data/g;
$test_main =~ s/TESTCODE_FILENAME/$test_case_file/g;
$test_main =~ s/FUNCTION_CODE//;
$test_main =~ s/DEP_CHECK_CODE/$dep_check_code/;
$test_main =~ s/DISPATCH_FUNCTION/$dispatch_code/;
$test_main =~ s/MAPPING_CODE/$mapping_code/;

$test_src .= << "END";
$test_main
END

#
# Write the source code to a file as required by command line arguments
#

if ($is_mbed)
{
    # Split the test suites into multiple files so that it fits into the MCU
    # FLASH memory.
    for my $i (0 .. $#test_data_chunks) {
        # Number each file (except the first) starting from 0
        my $file_num = ($i == 0) ? "" : ".".$i;
        my $test_file_i = $data_name.$file_num.".cpp";

        # Add the test data source code to the global variables
        my $test_src_i = $test_src;
        $test_src_i =~ s/TEST_DATA_CODE/$test_data_chunks[$i]/;

        # Write the test suite source to a file
        write_test_suite_src($test_file_i, $test_src_i);
    }
}
else
{
    write_test_suite_src($test_file, $test_src);
}

