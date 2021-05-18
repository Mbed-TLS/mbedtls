Remove MBEDTLS_CHECK_PARAMS option
----------------------------------

This change affects the way of how parameters are validated.

The option `MBEDTLS_CHECK_PARAMS` (disabled by default) enables certain kinds of
“parameter validation”. It covers two kinds of validations:

- In some functions that require a valid pointer, “parameter validation” checks
that the pointer is non-null. With the feature disabled, a null pointer is not
treated differently from any other invalid pointer, and typically leads to a
runtime crash. 90% of the uses of the feature are of this kind.
- In some functions that take an enum-like argument, “parameter validation”
checks that the value is a valid one. With the feature disabled, an invalid
value causes a silent default to one of the valid values.

The default reaction to a failed check is to call a function mbedtls_param_failed
which the application must provide. If this function returns, its caller returns
an error `MBEDTLS_ERR_xxx_BAD_INPUT_DATA`.

This feature is only used in some classic (non-PSA) cryptography modules. It is
not used in X.509, TLS or in PSA crypto, and it has not been implemented in all
classic crypto modules.

Removal of `MBEDTLS_CHECK_PARAMS` and all dependent features means changing
code that does something like this:
```
#if MBEDTLS_CHECK_PARAMS
#define VALIDATE(cond) do {if(cond) return BAD_INPUT_DATA;} while (0)
#else
#define VALIDATE(cond) do {} while (0)
#endif
...
VALIDATE(coin == HEADS || coin == TAILS);
VALIDATE(data != NULL);
if (coin == HEADS) heads();
else tails();
```
to something like this:
```
if (coin == HEADS) heads();
else if (coin == TAILS) tails();
else return BAD_INPUT_DATA;
```

Validation of enum-like values is somewhat useful, but not extremely important,
because the parameters concerned are usually constants in applications.

For more information see issue #4313.
