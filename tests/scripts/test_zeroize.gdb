# test_zeroize.gdb
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2017, ARM Limited, All Rights Reserved
#
# Purpose
#
# Run a test using the debugger to check that the mbedtls_zeroize() function in
# utils.h is not being optimized out by the compiler. To do so, the script
# loads the test program at programs/test/zeroize.c and sets a breakpoint at
# the last return statement in the main(). When the breakpoint is hit, the
# debugger manually checks the contents to be zeroized and checks that it is
# actually cleared.
#
# Note: This test requires that the test program is compiled with -g3.

set confirm off
file ./programs/test/zeroize
break zeroize.c:88

set args ./programs/test/zeroize.c
run

set $i = 0
set $len = sizeof(buf)
set $buf = buf

if exit_code != 0
    echo The program did not terminate correctly\n
    quit 1
end

while $i < $len
    if $buf[$i++] != 0
        echo The buffer at was not zeroized\n
        quit 1
    end
end

echo The buffer was correctly zeroized\n
quit 0
