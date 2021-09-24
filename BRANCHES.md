# Maintained branches

At any point in time, we have a number of maintained branches consisting of:

- The [`master`](https://github.com/ARMmbed/mbedtls/tree/master) branch:
  this always contains the latest release, including all publicly available
  security fixes.
- The [`development`](https://github.com/ARMmbed/mbedtls/tree/development) branch:
  this is where the current major version of Mbed TLS (version 3.x) is being
  prepared. It has API changes that make it incompatible with Mbed TLS 2.x,
  as well as all the new features and bug fixes and security fixes.
- The [`development_2.x`](https://github.com/ARMmbed/mbedtls/tree/development_2.x) branch:
  this branch retains the API of Mbed TLS 2.x, and has a subset of the
  features added after Mbed TLS 2.26.0 and bug fixes and security fixes.
- One or more long-time support (LTS) branches:
  these only get bug fixes and security fixes.

We use [Semantic Versioning](https://semver.org/). In particular, we maintain
API compatibility in the `master` branch across minor version changes (e.g.
the API of 3.(x+1) is backward compatible with 3.x). We only break API
compatibility on major version changes (e.g. from 3.x to 4.0). We also maintain
ABI compatibility within LTS branches; see the next section for details.

## Backwards Compatibility

We maintain API compatibility in released versions of Mbed TLS. If you have
code that's working and secure with Mbed TLS x.y.z and does not rely on
undocumented features, then you should be able to re-compile it without
modification with any later release x.y'.z' with the same major version
number, and your code will still build, be secure, and work.

Note that new releases of Mbed TLS may extend the API. Here are some
examples of changes that are common in minor releases of Mbed TLS, and are
not considered API compatibility breaks:

* Adding or reordering fields in a structure or union.
* Removing a field from a structure, unless the field is documented as public.
* Adding items to an enum.
* Returning an error code that was not previously documented for a function
  when a new error condition arises.
* Changing which error code is returned in a case where multiple error
  conditions apply.
* Changing the behavior of a function from failing to succeeding, when the
  change is a reasonable extension of the current behavior, i.e. the
  addition of a new feature.

There are rare exceptions where we break API compatibility: code that was
relying on something that became insecure in the meantime (for example,
crypto that was found to be weak) may need to be changed. In case security
comes in conflict with backwards compatibility, we will put security first,
but always attempt to provide a compatibility option.

## Long-time support branches

For the LTS branches, additionally we try very hard to also maintain ABI
compatibility (same definition as API except with re-linking instead of
re-compiling) and to avoid any increase in code size or RAM usage, or in the
minimum version of tools needed to build the code. The only exception, as
before, is in case those goals would conflict with fixing a security issue, we
will put security first but provide a compatibility option. (So far we never
had to break ABI compatibility in an LTS branch, but we occasionally had to
increase code size for a security fix.)

For contributors, see the [Backwards Compatibility section of
CONTRIBUTING](CONTRIBUTING.md#cackwords-compatibility).

## Current Branches

The following branches are currently maintained:

- [master](https://github.com/ARMmbed/mbedtls/tree/master)
- [`development`](https://github.com/ARMmbed/mbedtls/)
- [`development_2.x`](https://github.com/ARMmbed/mbedtls/tree/development_2.x)
- [`mbedtls-2.16`](https://github.com/ARMmbed/mbedtls/tree/mbedtls-2.16)
 maintained until at least the end of 2021, see
  <https://tls.mbed.org/tech-updates/blog/announcing-lts-branch-mbedtls-2.16>

Users are urged to always use the latest version of a maintained branch.
