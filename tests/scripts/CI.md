# CI instrumentation scripts
This is the documentation of the scripts that are used for deploying tests in the CI. These scripts provide following features:

- Ease of defining and maintaining different CI jobs.
- Reduce CI job complexity.
- Revision specific testing.
- Code reusability.
- Quality control via reviews and possibly testing in future.
- Debug CI scripts on host.

## CI Infrastructure and test entities relation
Following entity relation diagram shows the relationship between different components involved in Mbed TLS testing:
```

                                       1 ----------
                      -------------------|   CI   |
                      |                  ----------
                      |                       | 1
                      |                       |
                      |                       | m
                      |                  ----------
                      |                  |  Job   |
                      |                  ----------
                      |                       | m
                      |                       |
                      | m                     | m
                 ------------ m      m --------------- 1      m --------------------
                 | Platform |----------| Build & test|----------| Test environment |
                 ------------          ---------------          --------------------
                                              | 1
                                              |
                                              | 1
                                       -----------------
                                       | Configuration |
                                       -----------------

```
Terms used in the above diagram
- **1-----1** One to one relation
- **1-----m** One to many relation
- **m-----m** Many to many relation
- **CI** Continuous Integration infrastructure.
- **Job** A test campaign run on a particular revision of source. Like PR, nightly, release testing.
- **Build & test** A test script or bunch of commands that build and test under a specific config and environment.
- **Platform** Target platform. Like Ubuntu, Debian, FreeBSD etc.
- **Test environment** Environment to chang a test script behaviour. Like environment ```CC=gcc``` selects compiler GCC.
- **Configuration** Build configuration configured by preporocessor macros in ```config.h```.

## CI meta data
Based on the above entity relation diagram CI jobs are defined with the following structural metadata in json format:

```py
{
    "tests": {
        "make-gcc": {
            "build": "make",
            "environment": {"MAKE": "make", "CC": "gcc"},
            "tests": ["basic"],
            "platforms": ["debian-i386", "debian-x64"]
        },
        "cmake": {
            "build": "cmake",
            "environment": {"MAKE": "make", "CC": "gcc"},
            "tests": ["basic"],
            "platforms": ["debian-i386", "debian-x64"]
        },

        ...

       "iar8.2": {
            "config": "baremetal",
            "build": "cmake-iar8",
            "platforms": ["windows-tls"]
       },
       "msvc12-64": {
            "build": "msvc12-64",
            "platforms": ["windows-tls"]
        },
        "all.sh": {
            "script": "./tests/scripts/all.sh",
            "platforms": ["ubuntu-16.04-x64"]
        }
    },
    "campaigns": {
        "commit-tests": [
                "make-gcc", "cmake", "cmake-full", "cmake-asan", "gmake-clang",
                "cmake-clang", "mingw-make", "msvc12-32", "msvc12-64"],
        "release-tests": ["all.sh"]
    },
    "jobs": {
        "mbedtls-commit-tests": {
            "campaigns": ["commit-tests"]
        },
        "release-tests": {
            "campaigns": ["release-tests"]
        },
        "nightly": {
            "campaigns": ["commit-tests", "release-tests"]
        }
    }
}
```
The many-to-many relationship between **Job** and **Test Script** is further extended by introducing indirection using ```campaigns``` and ```tests```. This allows reuse of test definitions in multiple jobs. Hence, it reduces data redundancy.

Due to many-to-many relationship between **Job** and **build**, it is is keyed (referred) in above metadata with a name. Commands corresponding to this name are scripted in ```ciscript.sh``` and ```ciscript.bat``` for target platforms POSIX and Windows respectively.

## Test dispatch in CI
CI contains different jobs that run different set of tests on different events (pull request, periodic, manual etc) and different source revisions. Each job can use the scripts in this directory to discover corresponding tests and execute them. The idea here is to make CI agnostic of the test execution details and test scripts independent of CI framework. Script ```cibuilder.py``` can be used by a CI job to discover the tests it contains by running following command:

```
$ python cibuilder.py --list-tests <campaign name>
make-gcc-debian-9-i386|debian-9-i386
make-gcc-debian-9-x64|debian-9-x64
...
...
```
Above, the output displays a unique test name and target platform name. This information helps the CI job to run each test on required platform. Test script commands are explained in the next section.

## Test execution
Once a CI job spawns a test on a target platform it uses ```cibuilder.py``` again to generate the environment for the test. Following command does it:
```
$ python cibuilder.py --gen-env <test name>
Created cienv.sh
```
Example of ```cienv.sh``` for test ```cmake-full```:
```
export CC=gcc
export MAKE=make
export TEST_NAME=cmake-full-debian-i386
export BUILD=cmake
export RUN_FULL_TEST=1
```
```cienv.sh``` or ```cienv.bat``` is created for POSIX and Windows respectively. This script sets environment variables required for the test. This script is sourced by script ```ciscript.sh/bat``` that contains commands for each test. The CI job finally executes ```ciscript.sh/bat```:
Example:
```
./ciscript.sh
```

```ciscript.sh/bat``` scripts performs following tasks:

- Set configuration if specified.
- Check that required environment variables are set for the specified build.
- Execute specified build commands or run specified script.
- Run specified tests.

These scripts may define and name certain test configuration types (separate from those defined by ```config.pl```) and test collections that can be referenced by their name in the ```cijobs.json```. Please see documentation in the scripts for details.
