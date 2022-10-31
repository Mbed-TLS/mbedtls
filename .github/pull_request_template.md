## Description

Please write a few sentences describing the overall goals of the pull request's commits.



## Gatekeeper checklist

- [ ] **changelog** provided, or not required
- [ ] **backport** done, or not required
- [ ] **tests** provided, or not required



## Notes for the submitter

Pull requests cannot be accepted until the PR follows the [contributing guidelines](../CONTRIBUTING.md). In particular, each commit must have at least one `Signed-off-by:` line from the committer to certify that the contribution is made under the terms of the [Developer Certificate of Origin](../dco.txt).

#### Backporting

When there is a bug fix, it should be backported to all maintained and supported branches.
Changes do not have to be backported if:

- This PR is a new feature / enhancement
- This PR contains changes in the API. If this is true, and there is a need for the fix to be backported, the fix should be handled differently in the legacy branch

It is fine to defer providing a backport until the main PR is approved.

