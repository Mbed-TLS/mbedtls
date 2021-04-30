Remove the configuration to enable weak ciphersuites in SSL / TLS
-----------------------------------------------------------------

This does not affect users who use the default `config.h`, as this option was
already off by default.

If you were using a weak cipher, please switch to any of the modern,
recommended ciphersuites (based on AES-GCM, AES-CCM or ChachaPoly for example)
and if your peer doesn't support any, encourage them to upgrade their software.

If you were using a ciphersuite without encryption, you just have to
enable MBEDTLS_CIPHER_NULL_CIPHER now.
