# CI instrumentation scripts
Scripts under this directory are used for deploying tests in the CI. These are kept with source for following reasons:

- Ease of defining and maintaining different CI jobs.
- Reduce CI script complexity.
- Revision specific testing.
- Code reusability.
- Quality control via reviews and possibly testing in future.
- Debug CI scripts on host.

## CI Infrastructure and test entities relation
Following entity relation diagram shows the relationship between different components involved in Mbed TLS testing:
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
- **1-----1** One to one
- **1-----m** One to many
- **m-----m** Many to many
- **CI** Continuous Integration infrastructure.
- **Slave label** Label identifying a type of slave machines commissioned for running specific tests.
- **Job** A test campaign run on a particular revision of source. Like PR, nightly, release testing.
- **Test script** A test script or bunch of commands. It is executed on each required platform and environment.
- **Platform** Target platform. Like Ubuntu, Debian, FreeBSD etc.
- **Test environment** Environment to chang a test script behaviour. Like environment ```CC=gcc``` selects compiler GCC.

## CI meta data
Based on the above entity relation CI jobs can be defined with the meta data in following json format:

```py
ci_jobs = {
   "mbedtls-commit-tests": {
       "make-gcc": {
           "build": "make",
           "environment": {"MAKE": "make", "CC": "gcc"},
           "tests": ["basic"],
           "platforms": ["debian-i386", "debian-x64"]

       },
       "cmake-full":  {
           "build": "cmake",
           "environment": {"MAKE": "make", "CC": "gcc"},
           "tests": ["full"],
           "platforms": ["debian-i386", "debian-x64"]
       },
       
       "iar8": {
           "config": "baremetal",
           "build": "mingw-iar8",
           "platforms": ["windows-tls"]
       },
    ...
    
   },
   "release_tests": {
        'all.sh': {
            'script': './tests/scripts/all.sh',
            'platforms': ['ubuntu-16.04-x64']
        }
    }
}

```

Above, root element ```ci_jobs``` contains a collection of jobs in the form of dictionary elements. Job ```mbedtls-commit-tests``` further contains all the tests that need to be run as part of it. These tests may run in parallel depending on the CI implementation. Mechanism for running tests in parallel is CI specific and it is not limited by this solution.

For each test in the job target platform and optional execution environment are specified. Since the job and the test script have many-to-many relationship, commands of the test script are not defined here. They are referred by a name in this meta data and defined in ```ciscript.sh``` and ```ciscript.bat``` depending on the target platform.

## Test dispatch in CI
CI contains different jobs that run different set of tests on different events (pull request, periodic, manual etc) and different source revisions. Each job can use the scripts in this directory to discover corresponding tests and execute them. The idea here is to make CI agnostic of the test setup and commands. Script ```cibuilder.py``` can be used by a CI job to discover the tests it contains by running following command:

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
```
./ciscript.sh
```

```ciscript.sh/bat``` scripts contain commands for all the tests that are run by Mbed TLS CI. They performs following tasks:

- Set configuration if specified.
- Check that required environment variables are set for the specified build.
- Execute build commands.
- Run specified tests.

These scripts may define and name certain test configuration types (separate from those defined by ```config.pl```) and test collections that can be referenced by their name in the ```cijobs.json```. Please see scritps source for details.
