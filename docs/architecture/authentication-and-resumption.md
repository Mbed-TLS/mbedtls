## Client authentication
During a certificate-based handshake, a TLS server authenticates a client by
verifying the certificate chain provided by the client against a
certificate-authentication context, and by verifying that the client possesses
the private key associated with the leaf (end-entity) certificate. In
Mbed TLS, the certificate-authentication context consists of the certificate
verification profile, the trusted CA certificate chain, the CRLs, and the
authentication mode, which together determine the outcome of client certificate
verification.

During a PSK-based handshake, a TLS server authenticates a client by verifying
its knowledge of a pre-shared key associated with a PSK identity. In a PSK-based
handshake, the PSK-authentication context consists of the PSK identities and
associated keys accepted by the server.

Once a TLS connection has been established, an application operating an
Mbed TLS server identifies the client using the client's certificate in a
certificate-based handshake, or the PSK identity in a PSK-based handshake.

## Client authentication and session resumption
When resuming a server session in which client authentication took place, the
authentication guarantees provided to the application by the resumed session
should be equivalent to those provided by the original session.

### Resuming a session established through a certificate-based handshake
For a session established through a certificate-based handshake, this
means that verifying the original client certificate chain under the current
certificate-authentication context would yield the same result as in the
original session.

In practice, this property can be ensured in only two ways:

* The original client certificate chain is retained and verified again under the
current certificate-authentication context. This approach has a significant
memory cost, as the client certificate chain must be stored, and a CPU cost due
to certificate parsing and verification, reducing one of the main benefits of
session resumption.

* The current certificate-authentication context is identical to the original
one. It is difficult for the library to establish this property given the
complexity of a certificate-authentication context, and it is impossible in some
cases. In particular, when a trusted certificate callback or a verification
callback is configured through the `mbedtls_ssl_conf_ca_cb()` or
`mbedtls_ssl_conf_verify()` APIs, part of the verification logic is external to
the library and therefore cannot be compared by it. Consequently, only the
application can ensure that the conditions required for preserving the original
certificate-authentication guarantees still hold. In practice, this can be
achieved by resetting the session cache and invalidating previously issued
session tickets whenever the certificate-authentication context is modified.
Since the lifetime of cached sessions and session tickets is generally much
shorter than the timescale over which certificate-authentication contexts
change, this requirement is not expected to significantly reduce the
effectiveness of session resumption.

Taken together, these considerations suggest that the application should be
responsible for resetting the session cache and invalidating previously issued
session tickets whenever it modifies the certificate-authentication context.
Consequently, when resumption is enabled, the session cache and session-ticket
context are part of the certificate-authentication context.

#### Client identification by the server application

If the client certificate is not retained as part of the cached session or
session-ticket data, the identity derived by the application from the
certificate must be retained instead. This is necessary to ensure that, after
session resumption, the application can identify the client in the same way as
it could in the original session.

#### About certificate expiration

When resuming a session, one or more certificates in the certificate chain used
to establish the original session may have expired, meaning that a full
authentication would no longer succeed. However, in practice, session caches
and tickets are often configured with relatively short lifetimes (typically
from minutes to a few days), so requiring that none of the certificates in the
original chain have expired is unlikely to provide significant practical benefit.

### Resuming a session established through a PSK-based handshake

For a session established through a PSK-based handshake, preserving the original
authentication guarantees means that the PSK identity used in the original
handshake would still be accepted under the current PSK-authentication
context.

As with certificate-based authentication, only the application can ensure that
this property holds since the PSK selection logic resides in the
application-provided PSK callback configured through `mbedtls_ssl_conf_psk_cb()`.
In practice, this can also be achieved by resetting the session cache and
invalidating previously issued session tickets whenever the set of accepted PSK
identities and associated keys is modified.

The PSK identity must be retained as part of the cached session or
session-ticket data to ensure that, after session resumption, the application
can identify the client through the PSK identity.

### Considerations about the current implementation

The `MBEDTLS_SSL_KEEP_PEER_CERTIFICATE` configuration option allows the server
to retain the client's end-entity certificate after completion of the handshake
and to include it in session and ticket data. When this option is enabled, a
server can therefore identify a client after session resumption through the same
end-entity certificate that was available in the original session. However,
Mbed TLS does not currently include the peer certificate in TLS 1.3 tickets.

When this option is disabled, there is no mechanism for retaining either the
client's certificate or the identity derived by the application from that
certificate after completion of the handshake. In that configuration, a server
cannot identify a certificate-authenticated client after completion of the
handshake, nor after future resumption of a session established under that
context.

Likewise, there does not appear to be any mechanism for a server to identify a
client that was originally authenticated through a PSK-based handshake after
session resumption.

## Server authentication

Much of the discussion above also applies to server authentication. The main
difference is that the server is identified upfront by the client application.

In a PSK-based handshake, the corresponding context is simpler than for client
authentication: it is the single PSK selected by the application for the server.
The server authenticates itself by proving knowledge of that PSK.

For certificate-based server authentication, the TLS client verifies the server
certificate chain against a server certificate-authentication context, and
verifies that the server possesses the private key associated with the
leaf (end-entity) certificate. This context consists of the same elements as
the certificate-authentication context used for client authentication, plus the
expected server name checked during certificate verification.

### Server authentication and session resumption

The reasoning for certificate-based client authentication and session
resumption applies similarly to server authentication: a resumed client session
should provide the same server-authentication guarantees as the original
session. This means that verifying the original server certificate chain under
the current server-authentication context would yield the same result as in the
original session.

The main server-specific consideration is that the expected server name is part
of the server-authentication context. In practice, a client application should
only attempt to resume a session under the same server-authentication context
under which the session was established. If the trusted CA set,
certificate verification profile, authentication mode, verification callback, or
expected server name changes, the application should stop using sessions
established under the previous context. This means that a client application
must associate stored sessions and tickets with the server-authentication
context under which they were established.

## Client authentication and virtual servers

An application operating an Mbed TLS server can host several virtual servers
with different certificate-authentication contexts, different PSK-authentication
contexts, or both. During a handshake, the targeted virtual server is identified
through the SNI extension in the ClientHello.

In the case of a certificate-based handshake, the application selects the
certificate-authentication context associated with the targeted virtual server
within the SNI or certificate-selection callback. Within these callbacks, the
application can set the authentication mode using the `mbedtls_ssl_set_hs_authmode()`
API. It can also select the CA certificate chain and CRLs using
`mbedtls_ssl_set_hs_ca_chain()` if no trusted certificate callback has been
configured through the `mbedtls_ssl_conf_ca_cb()` API. Otherwise, selection of
the CA certificate chain and CRLs can be performed within the trusted certificate
callback.

In the case of a PSK-based handshake, the PSK identities and associated keys
valid for the targeted virtual server are selected by the PSK callback
configured through `mbedtls_ssl_conf_psk_cb()`.

### Considerations about the current implementation

In TLS 1.2, the PSK callback does not appear to have access to the targeted
virtual server. The callback is invoked while processing the `ClientKeyExchange`
message, and the hostname conveyed through the SNI extension in the `ClientHello`
does not appear to be available through any public API at that point. An
application could, however, retain the hostname itself when processing the SNI
callback and make it available to the PSK callback through application-specific
state.

## Client authentication, virtual servers and session resumption

To extend the approach described above from a single server per TLS context
to multiple virtual servers, the application should maintain a separate session
cache and a separate session-ticket context for each virtual server. Whenever
the certificate-authentication context or PSK-authentication context associated
with a virtual server is modified, the corresponding session cache should be
reset and any previously issued session tickets should be invalidated.

The session cache and session-ticket context are part of the
certificate-authentication context and PSK-authentication context associated
with a virtual server. Sharing them across virtual servers could allow a session
established under one authentication context to be resumed under a different one,
thereby violating the requirement that resumed sessions provide authentication
guarantees equivalent to those of the original session.

A per-virtual-server ticket context is also consistent with the guidance in
RFC 8446, Section 4.6.1:

> Clients MUST only resume if the new SNI value is valid for the server
  certificate presented in the original session and SHOULD only resume if the
  SNI value matches the one used in the original session. The latter is a
  performance optimization: normally, there is no reason to expect that different
  servers covered by a single certificate would be able to accept each other’s
  tickets; hence, attempting resumption in that case would waste a single-use
  ticket.

### Considerations about the current implementation

To support per-virtual-server certificate-authentication contexts and
PSK-authentication contexts, Mbed TLS would need one or more APIs, following
the model of `mbedtls_ssl_set_hs_authmode()` and `mbedtls_ssl_set_hs_ca_chain()`,
allowing the application to override, on a per-handshake basis, the session
cache and session-ticket context inherited from the configuration context.

## How to address client authentication issues when resuming

The minimum required changes are:
* For all APIs that contribute to certificate-authentication contexts or
PSK-authentication contexts, document that any modification of such a context
should result in resetting the associated session cache and invalidating tickets
issued under the associated session-ticket context.

An `mbedtls_ssl_cache_context` can be reset by calling
`mbedtls_ssl_cache_free()` followed by `mbedtls_ssl_cache_init()`. An
`mbedtls_ssl_ticket_context` can be reset by calling `mbedtls_ssl_ticket_free()`
followed by `mbedtls_ssl_ticket_init()` and `mbedtls_ssl_ticket_setup()`. Note
that calling `mbedtls_ssl_ticket_rotate()` is not sufficient for this purpose:
normal ticket-key rotation is designed to preserve the ability to decrypt
recently issued tickets.

* Add one or more APIs, following the model of `mbedtls_ssl_set_hs_authmode()`
and `mbedtls_ssl_set_hs_ca_chain()`, allowing the application to override,
on a per-handshake basis, the session cache and session-ticket context inherited
from the configuration context.

Additionally, the following improvements could be considered:
* When the SNI callback selects a certificate-authentication context for the
current handshake through `mbedtls_ssl_set_hs_authmode()` or
`mbedtls_ssl_set_hs_ca_chain()`, require the application to also select the
corresponding session cache and session-ticket context for the current
handshake, when the respective resumption mechanisms are enabled.
* Detect some obvious changes to a certificate-authentication context, such as
changes to the client authentication mode, and reject attempts to resume sessions
established under an obviously incompatible certificate-authentication context.

Open question:
* How should Mbed TLS preserve the client identity visible to the application
across session resumption, for both certificate-based and PSK-based authentication?
