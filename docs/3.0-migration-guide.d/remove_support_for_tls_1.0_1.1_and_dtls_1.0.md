Remove suport for TLS 1.0, 1.1 and DLTS 1.0
-------------------------------------------

This change affects users of the TLS 1.0, 1.1 and DTLS 1.0.

The versions of (D)TLS that are being removed are not as secure as the latest
versions. Keeping them in the library creates opportunities for misconfiguration
and possibly downgrade attacks. More generally, more code means a larger attack
surface, even if the code is supposedly not used.

The migration path is to adopt the latest versions of the protocol.
