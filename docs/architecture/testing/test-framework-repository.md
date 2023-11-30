# Mbed TLS test framework repository

## Goals

The test framework repository aims at fulfilling two goals:
. Avoid the duplication of test files between the mbedtls and TF-PSA-Crypto
  repositories.
. Avoid the maintenance of slightly identical test files among the supported
  branches of the mbedtls and TF-PSA-Crypto repositories.

That way we hope for test code to diverge as less as possible between the
two repositories and among their supported branches. This should ease
backports to supported branches.

The files that are considered to constitute the test framework repository are
the files located in the scripts and tests directories of the mbedtls
repository as they stand in the 3.x versions of Mbed TLS. The 2.28 LTS branch
is out of scope, its test code will not be restructured around the test
framework repository. In the following, "supported branches" means all the
supported branches but the mbedtls 2.28 LTS branch.

In terms of development efficiency, we cannot afford to move from the current
situation where the TLS and cryptographic development occurs within one
repository to a situation where the development occurs within three
repositories with frequent dependencies among pull requests of different
repositories. As for the test framework repository, to avoid that later
situation, the intent is for the files in that repository to be stable with
respect to the development and maintenance of TLS and cryptographic tests.
Most of the time, when working on an mbedtls or TF-PSA-Crypto pull request
involving some testing, there should be no need for any change in the test
framework. Given that, for example and at least at first sight, unit test
suites are not aimed to be part of the test framework.

It should be possible to build the libraries and the sample programs without
the test framework. The build systems and associated helper scripts should thus
not depend on the test framework.

## Test framework repository

The files in the test framework repository are versioned. Only one branch named
"main" is supported in the repository and this is the development branch. There
is no release of the test framework repository. The tip of its main branch
evolves with the needs of the tips of the supported branches of the mbedtls
and TF-PSA-Crypto repositories.

The files of the test framework repository are pulled into mbedtls and
TF-PSA-Crypto trees where they are used to check and test the mbedtls and
TF-PSA-Crypto code. Each commit of each supported branches in mbedtls and
TF-PSA-Crypto repositories is associated with one and only one commit of the
test framework repository. That is the version of the test framework repository
to pull in for the checks and tests of that particular mbedtls or TF-PSA-Crypto
commit. Furthermore, the tips of the supported branches in mbedtls and
TF-PSA-Crypto repositories are all associated with the tip of the test
framework repository main branch.

The natural way to achieve this with Git is for the test framework repository
to be pulled into mbedtls and TF-PSA-Crypto as a Git submodule. Each commit of
the mbedtls and TF-PSA-Crypto repositories defines the commit and thus the tree
of the test framework repository that resides in the submodule subdirectory.
The tips of the mbedtls and TF-PSA-Crypto supported branches all refer to the
tip of the test framework repository.

## mbedtls, TF-PSA-Crypto and the test framework repository

### Without the test framework submodule's code

Without the test framework submodule's code, the mbedtls and TF-PSA-Crypto
libraries build. So do the sample programs but a priori not the test and
helper programs and not the unit tests.

The scripts in the scripts directory at the root of the repositories are
independent of the test framework. The scripts in tests/scripts a priori
depend on the test framework code. The may work without at some point but there
is no guarantee it will remain that way.

### Release tarballs

Release tarballs of mbedtls and TF-PSA-Crypto contain the test framework code
associated to the released code. From a release tarball, a user can build
all libraries, all programs and all scripts are functional.

## Pull requests and CI

### Test framework repository

The development in the test framework repository follows the standard flow of
GitHub pull requests: pull requests are created, reviewed, tested with the CI
and eventually merged.

The test framework repository CI does not involve only its main branch but
also the supported branches of the mbedtls and TF-PSA-Crypto repositories. It
ensures that the new tip of the main branch that would result of the merge of a
pull request is compatible with all the tips of the supported branches of the
mbedtls and TF-PSA-Crypto repositories: when pulled into such a branch, the CI
tests of that branch still run successfully.

A pull request against the main branch of the test framework repository may
also depend on one or several pull requests against mbedtls and/or
TF-PSA-Crypto branches. It depends on them in the sense that its changes are
not compatible with the tips of the mbedtls and/or TF-PSA-Crypto supported
branches, only with the result of the merge of the aforementioned pull requests
with the current tips. This would be typically the case when some test
framework code is restructured: the test code in the mbedtls and TF-PSA-Crypto
supported branches would probably need to be adapted to this restructuration.
In that case, for the mbedtls and TF-PSA-Crypto branches impacted by the pull
request, the test framework CI validates the test framework repository pull
request against the merge of the pull requests it depends on with the
associated branch tips.

### mbedtls and TF-PSA-Crypto repositories

As part of a set of changes in one mbedtls or TF-PSA-Crypto supported branch,
some files that belong to the test framework repository may have to be
modified. Then, at least, two pull requests need to be created to review and
upstream the set of changes: one against the mbedtls or TF-PSA-Crypto branch,
the other one against the test framework repository main branch.

A pull request against an mbedtls or TF-PSA-Crypto supported branch can be
merged only if it references the tip of the test framework repository. This is
a simple and effective way of enforcing that the tips of the mbedtls and
TF-PSA-Crypto supported branches are always associated to the tip of the test
framework repository. As changes to the test framework are supposed to be
rare, this should be an acceptable constraint on the mbedtls and TF-PSA-Crypto
workflows.

The lifecycle of an mbedtls or TF-PSA-Crypto pull request for which changes in
the test framework are needed goes as follow:
. A pull request (PR) is created together with a pull request against the main
  branch of the test framework repository (TF-PR). The PR refers to the tip of
  the TF-PR for its CI testing.
. The two pull requests undergo the review process. As part of addressing
  comments on the PR, the test framework commit it refers to can be modified.
. If the TF-PR depends on the PR then it is tested against the merge of the PR
  with the head of the branch it targets. If it does not depend on the PR, it
  is tested against the tip of the branch targeted by the PR.
. The PR is tested by the CI using the test framework commit it refers to, a
  commit that is part or has been part of the TF-PR. The PR may pass the CI but
  as long as it does not refer to the tip of the test framework main branch, it
  cannot be merged.
. Once the TF-PR is merged, the PR can be updated to refer to the new tip of
  the test framework main branch, undergo a new run of CI and eventually be
  merged.
