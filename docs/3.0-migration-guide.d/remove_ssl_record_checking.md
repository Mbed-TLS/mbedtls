Remove MBEDTLS_SSL_RECORD_CHECKING option and enable its action by default
--------------------------------------------------------------------------

This change does not affect users who use the default config.h, as the
option MBEDTLS_SSL_RECORD_CHECKING was already on by default.

This option was added only to control compilation of one function,
mbedtls_ssl_check_record(), which is only useful in some specific cases, so it
was made optional to allow users who don't need it to save some code space.
However, the same effect can be achieve by using link-time garbage collection.

Users who changed the default setting of the option need to change the config/
build system to remove that change.
