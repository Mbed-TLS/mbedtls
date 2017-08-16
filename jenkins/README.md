# CI instrumentation scripts
Scripts under this directory are used for deploying tests in the CI. These are kept with source for following reasons:

- Ease of defining and maintaining different CI jobs.
- Reduce CI script complexity.
- Revision specific testing.
- Code reusability.
- Quality control via reviews and possibly testing in future.
- Debug CI scripts on host.

## CI Infrastructure and test entities relation
Following entity relation diagram shows the relation between different components involved in Mbed TLS testing:
```
              --------------- m        1 ----------
              | Slave label |------------|   CI   |
              ---------------            ----------
                      |1                      | 1
                      |                       |
                      |                       | m
                      |                  ----------
                      |                  |  Job   |
                      |                  ----------
                      |                       | m
                      |                       |
                      |1                      | m
                 ------------ m      m --------------- 1      m --------------------
                 | Platform |----------| Test script |----------| Test environment |
                 ------------          ---------------          --------------------

```
Terms used in the above diagram
- **CI** Continuous Integration infrastructure.
- **Slave label** Label identifying a type of slave machines commissioned for running specific tests.
- **Job** A test campaign run on a particular revision of source. Like PR, nightly, release testing.
- **Test script** A test script or bunch of commands. It is executed on each required platform and environment.
- **Platform** Target platform. Like Ubuntu, Debian, FreeBSD etc.
- **Test environment** Environment to chang a test script behaviour. Like environment ```CC=gcc``` selects compiler GCC.

## CI meta data
Based on above entity relation CI jobs can be defined with the meta data in following json format:

```py
ci_jobs = {
   "commit_tests": {
       'make-gcc': {
           'script': 'make',
           'environment': {'MAKE': 'make', 'CC': 'gcc'},
           'platforms': ['debian-9-i386', 'debian-9-x64'],

       },
       'gmake-gcc': {
           'script': 'make',
           'environment': {'MAKE': 'gmake', 'CC': 'gcc'},
           'platforms': ['debian-9-i386', 'debian-9-x64'],
       },
       'cmake': {
           'script': 'cmake',
           'environment': {'MAKE': 'gmake', 'CC': 'gcc'},
           'platforms': ['debian-9-i386', 'debian-9-x64'],
       },
       'cmake-full':  {
           'script': 'cmake-full',
           'environment': {'MAKE': 'gmake', 'CC': 'gcc'},
           'platforms': ['debian-9-i386', 'debian-9-x64'],
       },
       'cmake-asan': {
           'script': 'cmake-asan',
           'environment': {'MAKE': 'gmake', 'CC': 'clang'},
           'platforms': ['debian-9-i386', 'debian-9-x64'],
       },
       'mingw-make': {
           'script': 'mingw-make',
           'platforms': ['windows'],
       },
       'msvc12-32': {
           'script': 'msvc12-32',
           'platforms': ['windows'],
       },
       'msvc12-64': {
           'script': 'msvc12-64',
           'platforms': ['windows'],
       }
   },
   "release_tests": {
        'all.sh': {
            'script': './tests/scripts/all.sh',
            'platforms': ['ubuntu-16.04-x64']
        }
    }
}

```

Above, root element ```ci_jobs``` contains a collection of jobs in the form of dictionary elements. Job ```commit_tests``` further contains all the tests that need to be run as part of it. These tests may run in parallel depending on the CI implementation. Parallelization is out of scope of this solution.

For each test in the job target platform and optional execution environment is specified. Since the job and the test script have many to many relationship. Commands of the test script are not defined here. They are referred by a name in this meta data. They are defined elsewhere and explained later.

## Test dispatch in CI
CI needs different jobs to be able to trigger on different events like PR, periodic, manual etc. Each job can use the script in this directory to discover corresponding tests and execute them. The idea here is to make CI agnostic of the test script and environment. Script ```cibuilder.py``` can be used by a CI job to discover the tests it contains by running following command:

```
$ python cibuilder.py --list-tests <campaign name>
make-gcc-debian-9-i386|make-gcc|debian-9-i386
make-gcc-debian-9-x64|make-gcc|debian-9-x64
...
...
```
Above, the output displays a unique test name, test script name and platform name to execute it on. This information helps the CI job to run each test on required platform (test slave). Test script commands are explained in the next section.

## Test execution
Once the CI spawns a test on a target platform it uses ```cibuilder.py``` again to generate the environment for the test. Following command does it:
```
$ python cibuilder.py --gen-env <test name>
Created cienv.sh
```
```cienv.sh``` for POSIX and ```cienv.bat``` for Windows. This script contains values for the environment variables required for the test. This script is sourced by script ```ciscript.sh/bat``` that contains commands for each test:
```
./ciscript.sh <test name>
```

```ciscript.sh/bat``` scripts contain commands for all the tests that are run by Mbed TLS CI. It is invoked by the CI job with the test name. It checks if all the required environment variables for the test are defined and then executes the commands for that test. Following is a snippet of the ```ciscript.sh```:

```sh
#!/bin/sh

set -ex

if [ ! -x cienv.sh ]; then
    echo "Error: Environment file cenv.sh does not exists or it is not executable!"
    exit 1
fi

check_env(){
    for var in "$@"
    do
        eval value=\$$var
        if [ -z "${value}" ]; then
            echo "Error: Test $TEST_NAME: Required env var $var not set!"
            exit 1
        fi
    done
}

. ./cienv.sh
check_env TEST_NAME MBEDTLS_ROOT

cd $MBEDTLS_ROOT

if [ "$TEST_NAME" = "make" ]; then
    check_env CC MAKE
    ${MAKE} clean
    ${MAKE}
    ${MAKE} check
    ./programs/test/selftest

...
```
