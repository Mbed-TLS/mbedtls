# Pending changelog entry directory

This directory contains changelog entries that have not yet been merged
to the changelog file ([`../ChangeLog`](../ChangeLog)).

## Changelog entry file format

A changelog entry file must have the extension `*.txt` and must have the
following format:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Security
   * Change description.
   * Another change description.

Features
   * Yet another change description. This is a long change description that
     spans multiple lines.
   * Yet again another change description.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The permitted changelog entry categories are as follows:
<!-- Keep this synchronized with STANDARD_CATEGORIES in assemble_changelog.py! -->

    API changes
    Default behavior changes
    Requirement changes
    New deprecations
    Removals
    Features
    Security
    Bugfix
    Changes

Use “Changes” for anything that doesn't fit in the other categories, such as
performance, documentation and test improvements.

## How to write a changelog entry

Each entry starts with three spaces, an asterisk and a space. Continuation
lines start with 5 spaces. Lines wrap at 79 characters.

Write full English sentences with proper capitalization and punctuation. Use
the present tense. Use the imperative where applicable. For example: “Fix a
bug in mbedtls_xxx() ….”

Include GitHub issue numbers where relevant. Use the format “#1234” for an
Mbed TLS issue. Add other external references such as CVE numbers where
applicable.

Credit the author of the contribution if the contribution is not a member of
the Mbed TLS development team. Also credit bug reporters where applicable.

**Explain why, not how**. Remember that the audience is the users of the
library, not its developers. In particular, for a bug fix, explain the
consequences of the bug, not how the bug was fixed. For a new feature, explain
why one might be interested in the feature. For an API change or a deprecation,
explain how to update existing applications.

See [existing entries](../ChangeLog) for examples.

## How `ChangeLog` is updated

Run [`../scripts/assemble_changelog.py`](../scripts/assemble_changelog.py)
from a Git working copy
to move the entries from files in `ChangeLog.d` to the main `ChangeLog` file.
