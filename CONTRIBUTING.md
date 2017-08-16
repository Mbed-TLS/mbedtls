We gratefully accept bug reports and contributions from the community. There are some requirements we need to fulfill in order to be able to integrate contributions:

- All contributions, whether large or small require a Contributor's License Agreement (CLA) to be accepted. This is because source code can possibly fall under copyright law and we need your consent to share in the ownership of the copyright.
- To accept the Contributor’s Licence Agreement (CLA), individual contributors can do this by creating an mbed account and [accepting the online agreement here with a click through](https://developer.mbed.org/contributor_agreement/). Alternatively, for contributions from corporations, or those that do not wish to create an mbed account, a slightly different agreement can be found [here](https://www.mbed.com/en/about-mbed/contributor-license-agreements/). This agreement should be signed and returned to ARM as described in the instructions given.
- We would ask that contributions conform to [our coding standards](https://tls.mbed.org/kb/development/mbedtls-coding-standards), and that contributions should be fully tested before submission.
As with any open source project, contributions will be reviewed by the project team and community and may need some modifications to be accepted.

### Making a Contribution

1. [Check for open issues](https://github.com/ARMmbed/mbedtls/issues) or [start a discussion](https://tls.mbed.org/discussions) around a feature idea or a bug.
2. Fork the [mbed TLS repository on GitHub](https://github.com/ARMmbed/mbedtls) to start making your changes. As a general rule, you should use the "development" branch as a basis.
3. Write a test which shows that the bug was fixed or that the feature works as expected.
4. Send a pull request and bug us until it gets merged and published. Contributions may need some modifications, so work with us to get your change accepted. We will include your name in the ChangeLog :)

### Backports

mbed TLS maintains some legacy branches, which are release as LTS versions. As such, backporting to these branches should be handled according to the following rules:
  
1. If the contribution is a new feature\enhancement, no backporting is needed
2. Bug fixes should be backported, as long as the legacy branches have these bugs reproduced
3. Changes in the API, do not require backporting. If a bug fix introduced new API, such as new error codes, the bug fix should be implemented differently in the legacy branch.

It would be highly appreciated if a contribution would be backported to a legacy branch as well.  
At the moment, the legacy branches are:
  
1. [mbedtls-1.3](https://github.com/ARMmbed/mbedtls/tree/mbedtls-1.3)  
2. [mbedtls-2.1](https://github.com/ARMmbed/mbedtls/tree/mbedtls-2.1)  
3. [development](https://github.com/ARMmbed/mbedtls/tree/development)  

### Tests

As mentioned, tests that show the correctness of the feature\bug fix should be added to the Pull Request, if not such test exist.  
mbed TLS includes an elaborate test suite in `tests/` that initially requires Perl to generate the tests files (e.g. `test_suite_mpi.c`). These files are generated from a `function file` (e.g. `suites/test_suite_mpi.function`) and a `data file` (e.g. `suites/test_suite_mpi.data`). The function file contains the test functions. The data file contains the test cases, specified as parameters that will be passed to the test function.

### Continuous Integration Tests

Once a PR has been made, the Continuous Integration tests ( CI ) are triggered and run. You should follow the result of the CI tests, and fix failures.  


 