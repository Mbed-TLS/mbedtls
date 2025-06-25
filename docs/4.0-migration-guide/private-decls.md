## Private declarations

Since Mbed TLS 3.0, some things that are declared in a public header are not part of the stable application programming interface (API), but instead are considered private. Private elements may be removed or may have their semantics changed in a future minor release without notice.

### Understanding private declarations in public headers

In Mbed TLS 4.x, private elements in header files include:

* Anything appearing in a header file whose path contains `/private` (unless re-exported and documented in another non-private header).
* Structure and union fields declared with `MBEDTLS_PRIVATE(field_name)` in the source code, and appearing as `private_field_name` in the rendered documentation. (This was already the case since Mbed TLS 3.0.)
* Any preprocessor macro that is not documented with a Doxygen comment.
  In the source code, Doxygen comments start with `/**` or `/*!`. If a macro only has a comment above that starts with `/*`, the macro is considered private.
  In the rendered documentation, private macros appear with only an automatically rendered parameter list, value and location, but no custom text.
* Any declaration that is guarded by the preprocessor macro `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS`.

### Usage of private declarations

Some private declarations are present in public headers for technical reasons, because they need to be visible to the compiler. Others are present for historical reasons and may be cleaned up in later versions of the library. We strongly recommend against relying on these declarations, since they may be removed or may have their semantics changed without notice.

Note that Mbed TLS 4.0 still relies on some private interfaces of TF-PSA-Crypto 1.0. We expect to remove this reliance gradually in future minor releases.

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
