@echo off
goto :start

# ciscript.bat
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2018, ARM Limited, All Rights Reserved



################################################################
#### Documentation
################################################################

# Purpose
# -------
#
# To run a particular build step with specified environment and
# config followed by the specified tests.
#
# Notes for users
# ---------------
#
# Warning: the test is destructive. The specified build mode and
# configuration can and will arbitrarily change the current CMake
# configuration. After running this script, the CMake cache will
# be lost and CMake will no longer be initialised.
#
# Tools required
# ---------------------
# This script assumes the presence of the tools required by the
# scripts it runs. In addition it requires following tools:
#   1. mingw
#   2. Microsoft Visual Studio 12
#   3. IAR 8.2 with license setup
#
# Interface
# ---------------------
# This script requires environment variables to identify config,
# build type and tests. These are:
#   1. MBEDTLS_ROOT     - (mandatory) Toplevel directory.
#   2. BUILD            - (mandatory) Build type. See use below.
#   3. CONFIG           - (optional)  Argument for config.pl.
#   4. RUN_BASIC_TEST   - (optional)  Basic tests.
#   5. RUN_FULL_TEST    - (optional)  Full tests = basic + SSL + config.
#
# All the environment variables must be supplied via cienv.bat file that
# this script sources in the beginning.
#
# There are other environment variables required based on the build and
# tests selected. These are checked under each build type using function
# check_env().
#
# Notes for maintainers
# ---------------------
#
# This script dispatches tests in following order:
#   1. Change to specified configuration. (Optional)
#   2. Run specified build step. (Mandatory)
#   3. Run specified tests. (Optional)
#
# Tests are specified with following environment variables:
#   1. RUN_BASIC_TEST=1
#       * Execute CTest tests
#       * Execute ./programs/test/selftest
#   2. RUN_FULL_TEST=1
#       * Execute basic tests defined above
#       * Execute SSL tests
#       * Execute config tests
#
:start

set ENV_FILE=cienv.bat

REM check if cienv.bat is present
if not exist %ENV_FILE% (
    echo "Environment file %ENV_FILE% does not exist!"
    goto :error
)

call %ENV_FILE%

call :check_env TEST_NAME BUILD MBEDTLS_ROOT || goto :error

cd %MBEDTLS_ROOT%

REM ############################################################
REM  Change config if specified
REM ############################################################
if NOT "%CONFIG%"=="" (
    scripts\config.pl %CONFIG%
)

REM ############################################################
REM  Perform build step
REM ############################################################

if "%BUILD%"=="mingw-make" (
    cmake . -G "MinGW Makefiles" -DCMAKE_C_COMPILER="gcc"
    mingw32-make clean
    mingw32-make

) else if "%BUILD%"=="msvc12-32" (
    call "C:\\Program Files (x86)\\Microsoft Visual Studio 12.0\\VC\\vcvarsall.bat"
    cmake . -G "Visual Studio 12"
    MSBuild ALL_BUILD.vcxproj

) else if "%BUILD%"=="msvc12-64" (
    call "C:\\Program Files (x86)\\Microsoft Visual Studio 12.0\\VC\\vcvarsall.bat"
    cmake . -G "Visual Studio 12 Win64"
    MSBuild ALL_BUILD.vcxproj

) else if "%BUILD%"=="mingw-iar8" (
    perl scripts\config.pl baremetal
    cmake -D CMAKE_BUILD_TYPE:String=Check -DCMAKE_C_COMPILER="iccarm" -G "MinGW Makefiles" .
    mingw32-make lib

) else (
    echo "Error: Invalid build %BUILD%!"
    goto :error
)

REM ############################################################
REM  Perform tests
REM ############################################################

if "%RUN_BASIC_TEST%"=="1" (
    if "%BUILD%"=="mingw-make" (
        ctest -vv
    ) else (
        echo "Error: Basic tests only available under build: mingw-make!"
        goto :error
    )
)

goto :EOF

:check_env
setlocal enabledelayedexpansion
for %%x in (%*) do (
    call set val=%%%%x%%
    if "!val!"=="" (
        echo "Error: Env var %%x not set!"
        exit /b 1
    )
)
endlocal
goto :EOF

:error
REM for intentional error exit set errorlevel
if errorlevel == 0 ( errorlevel=1 )
echo Failed with error #%errorlevel%!
exit /b %errorlevel%

