Remove suport for TLS 1.0, 1.1 and DTLS 1.0
-------------------------------------------

This change affects users of the TLS 1.0, 1.1 and DTLS 1.0 protocols.

These versions have been deprecated by RFC 8996.
Keeping them in the library creates opportunities for misconfiguration
and possibly downgrade attacks. More generally, more code means a larger attack
surface, even if the code is supposedly not used.

The migration path is to adopt the latest versions of the protocol.

As a consequence of removing TLS 1.0, support for CBC record splitting was
also removed, as it was a work-around for a weakness in this particular
version. There is no migration path since the feature is no longer relevant.

As a consequence of currently supporting only one version of (D)TLS (and in the
future 1.3 which will have a different version negociation mechanism), support
for fallback SCSV (RFC 7507) was also removed. There is no migration path as
it's no longer useful with TLS 1.2 and later.

As a consequence of currently supporting only one version of (D)TLS (and in the
future 1.3 which will have a different concept of ciphersuites), support for
configuring ciphersuites separately for each version via
`mbedtls_ssl_conf_ciphersuites_for_version()` was removed. Use
`mbedtls_ssl_conf_ciphersuites()` to configure ciphersuites to use with (D)TLS
1.2; in the future a different API will be added for (D)TLS 1.3.
