#!/usr/bin/perl
#

use strict;

my $suite_dir = shift or die "Missing suite directory";
my $suite_name = shift or die "Missing suite name";
my $test_file = $suite_name.".c";
my $test_helper_file = $suite_dir."/helpers.function";
my $test_case_file = $suite_dir."/".$suite_name.".function";
my $test_data_file = $suite_dir."/".$suite_name.".data";

open(TEST_DATA, "$test_data_file") or die "Opening test cases '$test_data_file': $!";

my $line_separator = $/;
undef $/;

open(TEST_HELPERS, "$test_helper_file") or die "Opening test helpers '$test_helper_file': $!";
my $test_helpers = <TEST_HELPERS>;
close(TEST_HELPERS);

open(TEST_CASES, "$test_case_file") or die "Opening test cases '$test_case_file': $!";
my $test_cases = <TEST_CASES>;
close(TEST_CASES);
my ( $suite_header ) = $test_cases =~ /BEGIN_HEADER\n(.*?)\nEND_HEADER/s;

$/ = $line_separator;

open(TEST_FILE, ">$test_file") or die "Opening destination file '$test_file': $!";
print TEST_FILE << "END";
#include "fct.h"
$suite_header

$test_helpers

FCT_BGN()
{
    FCT_SUITE_BGN($suite_name)
    {
END

while (my $line = <TEST_DATA>)
{
    my $description = $line;
    $line = <TEST_DATA>;

    my $test_name = $description;
    $test_name =~ tr/A-Z \-/a-z__/;
    $test_name =~ tr/a-z0-9_//cd;

    # Carve the defines required for this test case
    my $requirements;
    if ($line =~ /^depends_on:/)
    {
        my $depends_on_line = $line;
        $line = <TEST_DATA>;

        ( $requirements ) = $depends_on_line =~ /^depends_on:(.*)$/;
    }
    
    my @var_req_arr = split(/:/, $requirements);
    my $pre_code;
    my $post_code;

    while (@var_req_arr)
    {
        my $req = shift @var_req_arr;

        $pre_code .= "#ifdef $req\n";
        $post_code .= "#endif\n";
    }

    my $command_line = $line;
    $line = <TEST_DATA>;

    # Carve the case name and variable values
    #
    my ( $case, $var_value ) = $command_line =~ /^([\w_]+):(.*)$/;

    # Escape the escaped colons (Not really escaped now)
    #
    $var_value =~ s/\\:/{colon_sign}/g;

    # Carve the case and variable definition
    #
    my ( $var_def, $case_code ) = $test_cases =~ /BEGIN_CASE\n$case:([^\n]*)\n(.*?)\nEND_CASE/s;

    my @var_def_arr = split(/:/, $var_def);
    my @var_value_arr = split(/:/, $var_value);

    while (@var_def_arr)
    {
        my $def = shift @var_def_arr;
        my $val = shift @var_value_arr;

        $case_code =~ s/\{$def\}/$val/g;
    }
    $case_code = "int ${test_name}_code_present = 0;\nTEST_ASSERT( ${test_name}_code_present == 1 );" if ($case_code =~ /^\s*$/);

    $case_code =~ s/{colon_sign}/:/g;
    $case_code =~ s/TEST_ASSERT/fct_chk/g;
    $case_code =~ s/TEST_EQUALS/fct_chk/g;

    $case_code =~ s/^/        /gm;


    print TEST_FILE << "END";
$pre_code
        FCT_TEST_BGN($test_name)
$case_code
        FCT_TEST_END();
$post_code
END
}

print TEST_FILE << "END";
    }
    FCT_SUITE_END();
}
FCT_END();
END

close(TEST_DATA);
close(TEST_FILE);
