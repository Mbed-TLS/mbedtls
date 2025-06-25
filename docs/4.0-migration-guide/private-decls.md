## Private declarations

Sample programs have not been fully updated yet and some of them might still
use APIs that are no longer public. You can recognize them by the fact that they
define the macro `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS` (or
`MBEDTLS_ALLOW_PRIVATE_ACCESS`) at the very top (before including headers). When
you see one of these two macros in a sample program, be aware it has not been
updated and parts of it do not demonstrate current practice.

We strongly recommend against defining `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS` or
`MBEDTLS_ALLOW_PRIVATE_ACCESS` in your own application. If you do so, your code
may not compile or work with future minor releases. If there's something you
want to do that you feel can only be achieved by using one of these two macros,
please reach out on github or the mailing list.
