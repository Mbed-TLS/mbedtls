Contributing
============
We gratefully accept bug reports and contributions from the community. There are some requirements we need to fulfill in order to be able to integrate contributions:

 - As with any open source project, contributions will be reviewed by the project team and community and may need some modifications to be accepted.
 - The contribution should not break API or ABI, unless there is a real justification for that. If there is an API change, the contribution, if accepted, will be merged only when there will be a major release.

Contributor License Agreement (CLA)
-----------------------------------
- All contributions, whether large or small, require a Contributor's License Agreement (CLA) to be accepted. This is because source code can possibly fall under copyright law and we need your consent to share in the ownership of the copyright.
- To accept the Contributor’s License Agreement (CLA), individual contributors can do this by creating an Mbed account and [accepting the online agreement here with a click through](https://developer.mbed.org/contributor_agreement/). Alternatively, for contributions from corporations, or those that do not wish to create an Mbed account, a slightly different agreement can be found [here](https://www.mbed.com/en/about-mbed/contributor-license-agreements/). This agreement should be signed and returned to Arm as described in the instructions given.

Coding Standards
----------------
- We would ask that contributions conform to [our coding standards](https://tls.mbed.org/kb/development/mbedtls-coding-standards), and that contributions are fully tested before submission, as mentioned in the [Tests](#tests) and [Continuous Integration](#continuous-integration-tests) sections.
- The code should be written in a clean and readable style.
- The code should be written in a portable generic way, that will benefit the whole community, and not only your own needs.
- The code should be secure, and will be reviewed from a security point of view as well.

Making a Contribution
---------------------
1. [Check for open issues](https://github.com/ARMmbed/mbedtls/issues) or [start a discussion](https://tls.mbed.org/discussions) around a feature idea or a bug.
1. Fork the [Mbed TLS repository on GitHub](https://github.com/ARMmbed/mbedtls) to start making your changes. As a general rule, you should use the ["development" branch](https://github.com/ARMmbed/mbedtls/tree/development) as a basis.
1. Write a test which shows that the bug was fixed or that the feature works as expected.
1. Send a pull request (PR) and work with us until it gets merged and published. Contributions may need some modifications, so a few rounds of review and fixing may be necessary. We will include your name in the ChangeLog :)
1. For quick merging, the contribution should be short, and concentrated on a single feature or topic. The larger the contribution is, the longer it would take to review it and merge it.
1. Mbed TLS is released under the Apache license, and as such, all the added files should include the Apache license header.

Long Term Support Branches
--------------------------
Mbed TLS maintains several LTS (Long Term Support) branches, which are maintained continuously for a given period. The LTS branches are provided to allow users of the library to have a maintained version of the library which contains security fixes and fixes for other defects, without encountering any API changes or requiring changes in their own code. To allow users to take advantage of the LTS branches, these branches maintain backwards compatibility for both the public API and ABI.

When backporting to these branches please observe the following rules:

 1. Generally, all changes to the library which change the API cannot be backported.
 2. All bug fixes must be backported to the LTS branches if they correct a defect in an LTS branch. If a bug fix introduces a change to the API such as a new function, the fix should be reworked to avoid the API change. API changes without very strong justification are unlikely to be accepted.
 3. If a contribution is a new feature or enhancement, no backporting is required. Exceptions to this may be addtional test cases or quality improvements such as changes to scripts.

It would be highly appreciated if contributions are backported to LTS branches in addition to the [development branch](https://github.com/ARMmbed/mbedtls/tree/development).

Currently maintained LTS branches are:

1. [mbedtls-2.1](https://github.com/ARMmbed/mbedtls/tree/mbedtls-2.1)
1. [mbedtls-2.7](https://github.com/ARMmbed/mbedtls/tree/mbedtls-2.7)

Tests
-----
As mentioned, tests that show the correctness of the feature or bug fix should be added to the pull request, if no such tests exist.  
Mbed TLS includes an elaborate test suite in `tests/` that initially requires Perl to generate the tests files (e.g. `test_suite_mpi.c`). These files are generated from a `function file` (e.g. `suites/test_suite_mpi.function`) and a `data file` (e.g. `suites/test_suite_mpi.data`). The function file contains the test functions. The data file contains the test cases, specified as parameters that will be passed to the test function.

Sample applications, if needed, should be modified as well.

Continuous Integration Tests
----------------------------
Once a PR has been made, the Continuous Integration (CI) tests are triggered and run. You should follow the result of the CI tests, and fix failures. 
It is advised to enable the [githooks scripts](https://github.com/ARMmbed/mbedtls/tree/development/tests/git-scripts) prior to pushing your changes, for catching some of the issues as early as possible.

Documentation
-------------
Mbed TLS should be well documented. If documentation is needed, speak out!

1. All interfaces should be documented through Doxygen. New APIs should introduce Doxygen documentation.
1. Complex parts in the code should include comments.
1. If needed, a Readme file is advised.
1. If a [Knowledge Base (KB)](https://tls.mbed.org/kb) article should be added, write this as a comment in the PR description.
1. A [ChangeLog](https://github.com/ARMmbed/mbedtls/blob/development/ChangeLog) entry should be added for this contribution.
