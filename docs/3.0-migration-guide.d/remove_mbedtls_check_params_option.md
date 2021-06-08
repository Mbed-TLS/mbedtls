Remove MBEDTLS_CHECK_PARAMS option
----------------------------------

This change does not affect users who use the default configuration; it only
affects users who enabled that option.

The option `MBEDTLS_CHECK_PARAMS` (disabled by default) enabled certain kinds
of “parameter validation”. It covered two kinds of validations:

- In some functions that require a valid pointer, “parameter validation” checks
that the pointer is non-null. With the feature disabled, a null pointer is not
treated differently from any other invalid pointer, and typically leads to a
runtime crash. 90% of the uses of the feature are of this kind.
- In some functions that take an enum-like argument, “parameter validation”
checks that the value is a valid one. With the feature disabled, an invalid
value causes a silent default to one of the valid values.

The default reaction to a failed check was to call a function
`mbedtls_param_failed()` which the application had to provide. If this function
returned, its caller returned an error `MBEDTLS_ERR_xxx_BAD_INPUT_DATA`.

This feature was only used in some classic (non-PSA) cryptography modules. It was
not used in X.509, TLS or in PSA crypto, and it was not implemented in all
classic crypto modules.

This feature has been removed. The library no longer checks for NULL pointers;
checks for enum-like arguments will be kept or re-introduced on a case-by-case
basis, but their presence will no longer be dependent on a compile-time option.

Validation of enum-like values is somewhat useful, but not extremely important,
because the parameters concerned are usually constants in applications.

For more information see issue #4313.
