# components-compiler.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains the test components that are executed by all.sh

################################################################
#### Compiler Testing
################################################################


support_build_tfm_armcc () {
    support_build_armcc
}

component_build_tfm_armcc () {
    # test the TF-M configuration can build cleanly with various warning flags enabled
    cp configs/config-tfm.h "$CONFIG_H"

    msg "build: TF-M config, armclang armv7-m thumb2"
    armc6_build_test "--target=arm-arm-none-eabi -march=armv7-m -mthumb -Os -std=c99 -Werror -Wall -Wextra -Wwrite-strings -Wpointer-arith -Wimplicit-fallthrough -Wshadow -Wvla -Wformat=2 -Wno-format-nonliteral -Wshadow -Wasm-operand-widths -Wunused -I../tests/include/spe"
}

support_test_aesni_m32_clang () {
    # clang >= 4 is required to build with target attributes
    support_test_aesni_m32 && [[ $(clang_version) -ge 4 ]]
}

component_test_aesni_m32_clang () {

    scripts/config.py set MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    scripts/config.py set MBEDTLS_HAVE_ASM

    # test the intrinsics implementation with clang
    msg "AES tests, test intrinsics (clang)"
    make clean
    make CC=clang CFLAGS='-m32 -Werror -Wall -Wextra' LDFLAGS='-m32'
    # check that we built intrinsics - this should be used by default when supported by the compiler
    ./programs/test/selftest aes | grep "AESNI code" | grep -q "intrinsics"
    grep -q "AES note: using AESNI" ./programs/test/selftest
    grep -q "AES note: built-in implementation." ./programs/test/selftest
    grep -q mbedtls_aesni_has_support ./programs/test/selftest
}

# For timebeing, no aarch64 gcc available in CI and no arm64 CI node.

support_build_aes_aesce_armcc () {
    support_build_armcc
}

support_test_block_cipher_no_decrypt_aesce_armcc () {
    support_build_armcc
}

test_build_opt () {
    info=$1 cc=$2; shift 2
    $cc --version
    for opt in "$@"; do
          msg "build/test: $cc $opt, $info" # ~ 30s
          make CC="$cc" CFLAGS="$opt -std=c99 -pedantic -Wall -Wextra -Werror"
          # We're confident enough in compilers to not run _all_ the tests,
          # but at least run the unit tests. In particular, runs with
          # optimizations use inline assembly whereas runs with -O0
          # skip inline assembly.
          make test # ~30s
          make clean
    done
}

# For FreeBSD we invoke the function by name so this condition is added
# to disable the existing test_clang_opt function for linux.
if [[ $(uname) != "Linux" ]]; then
    component_test_clang_opt () {
        scripts/config.py full
        test_build_opt 'full config' clang -O0 -Os -O2
    }
fi

component_test_clang_latest_opt () {
    scripts/config.py full
    test_build_opt 'full config' "$CLANG_LATEST" -O0 -Os -O2
}

support_test_clang_latest_opt () {
    type "$CLANG_LATEST" >/dev/null 2>/dev/null
}

component_test_clang_earliest_opt () {
    scripts/config.py full
    test_build_opt 'full config' "$CLANG_EARLIEST" -O0
}

support_test_clang_earliest_opt () {
    type "$CLANG_EARLIEST" >/dev/null 2>/dev/null
}

component_test_gcc_latest_opt () {
    scripts/config.py full
    test_build_opt 'full config' "$GCC_LATEST" -O0 -Os -O2
}

support_test_gcc_latest_opt () {
    type "$GCC_LATEST" >/dev/null 2>/dev/null
}

component_test_gcc_earliest_opt () {
    scripts/config.py full
    test_build_opt 'full config' "$GCC_EARLIEST" -O0
}

support_test_gcc_earliest_opt () {
    type "$GCC_EARLIEST" >/dev/null 2>/dev/null
}

component_build_arm_none_eabi_gcc () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc -O1, baremetal+debug" # ~ 10s
    scripts/config.py baremetal
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" LD="${ARM_NONE_EABI_GCC_PREFIX}ld" CFLAGS='-std=c99 -Werror -Wall -Wextra -O1' lib

    msg "size: ${ARM_NONE_EABI_GCC_PREFIX}gcc -O1, baremetal+debug"
    ${ARM_NONE_EABI_GCC_PREFIX}size -t library/*.o
    ${ARM_NONE_EABI_GCC_PREFIX}size -t ${PSA_CORE_PATH}/*.o
    ${ARM_NONE_EABI_GCC_PREFIX}size -t ${BUILTIN_SRC_PATH}/*.o
}

component_build_arm_linux_gnueabi_gcc_arm5vte () {
    msg "build: ${ARM_LINUX_GNUEABI_GCC_PREFIX}gcc -march=arm5vte, baremetal+debug" # ~ 10s
    scripts/config.py baremetal
    # Build for a target platform that's close to what Debian uses
    # for its "armel" distribution (https://wiki.debian.org/ArmEabiPort).
    # See https://github.com/Mbed-TLS/mbedtls/pull/2169 and comments.
    # Build everything including programs, see for example
    # https://github.com/Mbed-TLS/mbedtls/pull/3449#issuecomment-675313720
    make CC="${ARM_LINUX_GNUEABI_GCC_PREFIX}gcc" AR="${ARM_LINUX_GNUEABI_GCC_PREFIX}ar" CFLAGS='-Werror -Wall -Wextra -march=armv5te -O1' LDFLAGS='-march=armv5te'

    msg "size: ${ARM_LINUX_GNUEABI_GCC_PREFIX}gcc -march=armv5te -O1, baremetal+debug"
    ${ARM_LINUX_GNUEABI_GCC_PREFIX}size -t library/*.o
    ${ARM_LINUX_GNUEABI_GCC_PREFIX}size -t ${PSA_CORE_PATH}/*.o
    ${ARM_LINUX_GNUEABI_GCC_PREFIX}size -t ${BUILTIN_SRC_PATH}/*.o
}

support_build_arm_linux_gnueabi_gcc_arm5vte () {
    type ${ARM_LINUX_GNUEABI_GCC_PREFIX}gcc >/dev/null 2>&1
}

component_build_arm_none_eabi_gcc_arm5vte () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc -march=arm5vte, baremetal+debug" # ~ 10s
    scripts/config.py baremetal
    # This is an imperfect substitute for
    # component_build_arm_linux_gnueabi_gcc_arm5vte
    # in case the gcc-arm-linux-gnueabi toolchain is not available
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" CFLAGS='-std=c99 -Werror -Wall -Wextra -march=armv5te -O1' LDFLAGS='-march=armv5te' SHELL='sh -x' lib

    msg "size: ${ARM_NONE_EABI_GCC_PREFIX}gcc -march=armv5te -O1, baremetal+debug"
    ${ARM_NONE_EABI_GCC_PREFIX}size -t library/*.o
    ${ARM_NONE_EABI_GCC_PREFIX}size -t ${PSA_CORE_PATH}/*.o
    ${ARM_NONE_EABI_GCC_PREFIX}size -t ${BUILTIN_SRC_PATH}/*.o
}

component_build_arm_none_eabi_gcc_m0plus () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc -mthumb -mcpu=cortex-m0plus, baremetal_size" # ~ 10s
    scripts/config.py baremetal_size
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" LD="${ARM_NONE_EABI_GCC_PREFIX}ld" CFLAGS='-std=c99 -Werror -Wall -Wextra -mthumb -mcpu=cortex-m0plus -Os' lib

    msg "size: ${ARM_NONE_EABI_GCC_PREFIX}gcc -mthumb -mcpu=cortex-m0plus -Os, baremetal_size"
    ${ARM_NONE_EABI_GCC_PREFIX}size -t library/*.o
    ${ARM_NONE_EABI_GCC_PREFIX}size -t ${PSA_CORE_PATH}/*.o
    ${ARM_NONE_EABI_GCC_PREFIX}size -t ${BUILTIN_SRC_PATH}/*.o
    for lib in library/*.a; do
        echo "$lib:"
        ${ARM_NONE_EABI_GCC_PREFIX}size -t $lib | grep TOTALS
    done
}

component_build_arm_none_eabi_gcc_no_udbl_division () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc -DMBEDTLS_NO_UDBL_DIVISION, make" # ~ 10s
    scripts/config.py baremetal
    scripts/config.py set MBEDTLS_NO_UDBL_DIVISION
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" LD="${ARM_NONE_EABI_GCC_PREFIX}ld" CFLAGS='-std=c99 -Werror -Wall -Wextra' lib
    echo "Checking that software 64-bit division is not required"
    not grep __aeabi_uldiv library/*.o
    not grep __aeabi_uldiv ${PSA_CORE_PATH}/*.o
    not grep __aeabi_uldiv ${BUILTIN_SRC_PATH}/*.o
}

component_build_arm_none_eabi_gcc_no_64bit_multiplication () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc MBEDTLS_NO_64BIT_MULTIPLICATION, make" # ~ 10s
    scripts/config.py baremetal
    scripts/config.py set MBEDTLS_NO_64BIT_MULTIPLICATION
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" LD="${ARM_NONE_EABI_GCC_PREFIX}ld" CFLAGS='-std=c99 -Werror -O1 -march=armv6-m -mthumb' lib
    echo "Checking that software 64-bit multiplication is not required"
    not grep __aeabi_lmul library/*.o
    not grep __aeabi_lmul ${PSA_CORE_PATH}/*.o
    not grep __aeabi_lmul ${BUILTIN_SRC_PATH}/*.o
}

component_build_arm_clang_thumb () {
    # ~ 30s

    scripts/config.py baremetal

    msg "build: clang thumb 2, make"
    make clean
    make CC="clang" CFLAGS='-std=c99 -Werror -Os --target=arm-linux-gnueabihf -march=armv7-m -mthumb' lib

    # Some Thumb 1 asm is sensitive to optimisation level, so test both -O0 and -Os
    msg "build: clang thumb 1 -O0, make"
    make clean
    make CC="clang" CFLAGS='-std=c99 -Werror -O0 --target=arm-linux-gnueabihf -mcpu=arm1136j-s -mthumb' lib

    msg "build: clang thumb 1 -Os, make"
    make clean
    make CC="clang" CFLAGS='-std=c99 -Werror -Os --target=arm-linux-gnueabihf -mcpu=arm1136j-s -mthumb' lib
}

component_build_armcc () {
    msg "build: ARM Compiler 5"
    scripts/config.py baremetal
    # armc[56] don't support SHA-512 intrinsics
    scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT

    # older versions of armcc/armclang don't support AESCE_C on 32-bit Arm
    scripts/config.py unset MBEDTLS_AESCE_C

    # Stop armclang warning about feature detection for A64_CRYPTO.
    # With this enabled, the library does build correctly under armclang,
    # but in baremetal builds (as tested here), feature detection is
    # unavailable, and the user is notified via a #warning. So enabling
    # this feature would prevent us from building with -Werror on
    # armclang. Tracked in #7198.
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT

    scripts/config.py set MBEDTLS_HAVE_ASM

    make CC="$ARMC5_CC" AR="$ARMC5_AR" WARNING_CFLAGS='--strict --c99' lib

    msg "size: ARM Compiler 5"
    "$ARMC5_FROMELF" -z library/*.o
    "$ARMC5_FROMELF" -z ${PSA_CORE_PATH}/*.o
    "$ARMC5_FROMELF" -z ${BUILTIN_SRC_PATH}/*.o

    # Compile mostly with -O1 since some Arm inline assembly is disabled for -O0.

    # ARM Compiler 6 - Target ARMv7-A
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv7-a"

    # ARM Compiler 6 - Target ARMv7-M
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv7-m"

    # ARM Compiler 6 - Target ARMv7-M+DSP
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv7-m+dsp"

    # ARM Compiler 6 - Target ARMv8-A - AArch32
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv8.2-a"

    # ARM Compiler 6 - Target ARMv8-M
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv8-m.main"

    # ARM Compiler 6 - Target Cortex-M0 - no optimisation
    armc6_build_test "-O0 --target=arm-arm-none-eabi -mcpu=cortex-m0"

    # ARM Compiler 6 - Target Cortex-M0
    armc6_build_test "-Os --target=arm-arm-none-eabi -mcpu=cortex-m0"

    # ARM Compiler 6 - Target ARMv8.2-A - AArch64
    #
    # Re-enable MBEDTLS_AESCE_C as this should be supported by the version of armclang
    # that we have in our CI
    scripts/config.py set MBEDTLS_AESCE_C
    armc6_build_test "-O1 --target=aarch64-arm-none-eabi -march=armv8.2-a+crypto"
}

support_build_armcc () {
    armc5_cc="$ARMC5_BIN_DIR/armcc"
    armc6_cc="$ARMC6_BIN_DIR/armclang"
    (check_tools "$armc5_cc" "$armc6_cc" > /dev/null 2>&1)
}

component_build_mingw () {
    msg "build: Windows cross build - mingw64, make (Link Library)" # ~ 30s
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror -Wall -Wextra -maes -msse2 -mpclmul' WINDOWS_BUILD=1 lib programs

    # note Make tests only builds the tests, but doesn't run them
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror -maes -msse2 -mpclmul' WINDOWS_BUILD=1 tests
    make WINDOWS_BUILD=1 clean

    msg "build: Windows cross build - mingw64, make (DLL)" # ~ 30s
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror -Wall -Wextra -maes -msse2 -mpclmul' WINDOWS_BUILD=1 SHARED=1 lib programs
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror -Wall -Wextra -maes -msse2 -mpclmul' WINDOWS_BUILD=1 SHARED=1 tests
    make WINDOWS_BUILD=1 clean

    msg "build: Windows cross build - mingw64, make (Library only, default config without MBEDTLS_AESNI_C)" # ~ 30s
    ./scripts/config.py unset MBEDTLS_AESNI_C #
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror -Wall -Wextra' WINDOWS_BUILD=1 lib
    make WINDOWS_BUILD=1 clean
}

support_build_mingw () {
    case $(i686-w64-mingw32-gcc -dumpversion 2>/dev/null) in
        [0-5]*|"") false;;
        *) true;;
    esac
}

component_test_zeroize () {
    # Test that the function mbedtls_platform_zeroize() is not optimized away by
    # different combinations of compilers and optimization flags by using an
    # auxiliary GDB script. Unfortunately, GDB does not return error values to the
    # system in all cases that the script fails, so we must manually search the
    # output to check whether the pass string is present and no failure strings
    # were printed.

    # Don't try to disable ASLR. We don't care about ASLR here. We do care
    # about a spurious message if Gdb tries and fails, so suppress that.
    gdb_disable_aslr=
    if [ -z "$(gdb -batch -nw -ex 'set disable-randomization off' 2>&1)" ]; then
        gdb_disable_aslr='set disable-randomization off'
    fi

    for optimization_flag in -O2 -O3 -Ofast -Os; do
        for compiler in clang gcc; do
            msg "test: $compiler $optimization_flag, mbedtls_platform_zeroize()"
            make programs CC="$compiler" DEBUG=1 CFLAGS="$optimization_flag"
            gdb -ex "$gdb_disable_aslr" -x tests/scripts/test_zeroize.gdb -nw -batch -nx 2>&1 | tee test_zeroize.log
            grep "The buffer was correctly zeroized" test_zeroize.log
            not grep -i "error" test_zeroize.log
            rm -f test_zeroize.log
            make clean
        done
    done
}
