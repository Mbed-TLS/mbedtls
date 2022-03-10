TLS 1.3 support
===============

Overview
--------

Mbed TLS provides a minimum viable implementation of the TLS 1.3 protocol
defined in the "MVP definition" section below. The TLS 1.3 support enablement
is controlled by the MBEDTLS_SSL_PROTO_TLS1_3 configuration option.

The development of the TLS 1.3 protocol is based on the TLS 1.3 prototype
located at https://github.com/hannestschofenig/mbedtls. The prototype is
itself based on a version of the development branch that we aim to keep as
recent as possible (ideally the head) by merging regularly commits of the
development branch into the prototype. The section "Prototype upstreaming
status" below describes what remains to be upstreamed.


MVP definition
--------------

- Overview

  - The TLS 1.3 MVP implements only the client side of the protocol.

  - The TLS 1.3 MVP supports ECDHE key establishment.

  - The TLS 1.3 MVP does not support DHE key establishment.

  - The TLS 1.3 MVP does not support pre-shared keys, including any form of
    session resumption. This implies that it does not support sending early
    data (0-RTT data).

  - The TLS 1.3 MVP supports the authentication of the server by the client
    but does not support authentication of the client by the server. In terms
    of TLS 1.3 authentication messages, this means that the TLS 1.3 MVP
    supports the processing of the Certificate and CertificateVerify messages
    but not of the CertificateRequest message.

  - The TLS 1.3 MVP does not support the handling of server HelloRetryRequest
    message. In practice, this means that the handshake will fail if the MVP
    does not provide in its ClientHello the shared secret associated to the
    group selected by the server for key establishement. For more information,
    see the comment associated to the `key_share` extension below.

  - If the TLS 1.3 MVP receives a HelloRetryRequest or a CertificateRequest
    message, it aborts the handshake with an handshake_failure closure alert
    and the `mbedtls_ssl_handshake()` returns in error with the
    `MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE` error code.

- Supported cipher suites: depends on the library configuration. Potentially
  all of them:
  TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
  TLS_AES_128_CCM_SHA256 and TLS_AES_128_CCM_8_SHA256.

- Supported ClientHello extensions:

  | Extension                    |   MVP   | Prototype (1) |
  | ---------------------------- | ------- | ------------- |
  | server_name                  | YES     | YES           |
  | max_fragment_length          | no      | YES           |
  | status_request               | no      | no            |
  | supported_groups             | YES     | YES           |
  | signature_algorithms         | YES     | YES           |
  | use_srtp                     | no      | no            |
  | heartbeat                    | no      | no            |
  | apln                         | no      | YES           |
  | signed_certificate_timestamp | no      | no            |
  | client_certificate_type      | no      | no            |
  | server_certificate_type      | no      | no            |
  | padding                      | no      | no            |
  | key_share                    | YES (2) | YES           |
  | pre_shared_key               | no      | YES           |
  | psk_key_exchange_modes       | no      | YES           |
  | early_data                   | no      | YES           |
  | cookie                       | no      | YES           |
  | supported_versions           | YES (3) | YES           |
  | certificate_authorities      | no      | no            |
  | post_handshake_auth          | no      | no            |
  | signature_algorithms_cert    | no      | no            |

  (1) This is just for comparison.

  (2) The MVP sends only one shared secret corresponding to the configured
      preferred group. This could end up with connection failure if the
      server does not support our preferred curve, as the MVP does not implement
      HelloRetryRequest. The preferred group is the group of the first curve in
      the list of allowed curves as defined by the configuration. The allowed
      curves are by default ordered as follows: `x25519`, `secp256r1`,
      `secp384r1` and finally `secp521r1`. Note that, in the absence of an
      application profile standard specifying otherwise, section 9.1 of the
      specification rather promotes curve `secp256r1` to be supported over
      curve `x25519`. The MVP would, however, rather keep the preference order
      currently promoted by Mbed TLS as this applies to TLS 1.2 as well, and
      changing the order only for TLS1.3 would be potentially difficult.
      In the unlikely event a server does not support curve `x25519` but does
      support curve `secp256r1`, curve `secp256r1` can be set as the preferred
      curve through the `mbedtls_ssl_conf_curves()` API.

  (3) The MVP proposes only TLS 1.3 and does not support version negotiation.
      Out-of-protocol fallback is supported though if the Mbed TLS library
      has been built to support both TLS 1.3 and TLS 1.2: just set the
      maximum of the minor version of the SSL configuration to
      MBEDTLS_SSL_MINOR_VERSION_3 (`mbedtls_ssl_conf_min_version()` API) and
      re-initiate a server handshake.

- Supported groups: depends on the library configuration.
  Potentially all ECDHE groups but x448:
  secp256r1, x25519, secp384r1 and secp521r1.

  Finite field groups (DHE) are not supported.

- Supported signature algorithms (both for certificates and CertificateVerify):
  depends on the library configuration.
  Potentially:
  rsa_pkcs1_sha256, rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256,
  ecdsa_secp384r1_sha384 and ecdsa_secp521r1_sha512.

  Note that in absence of an application profile standard specifying otherwise
  the three first ones in the list above are mandatory (see section 9.1 of the
  specification).

- Supported versions:

  - TLS 1.2 and TLS 1.3 but version negotiation is not supported.

  - TLS 1.3 cannot be enabled in the build (MBEDTLS_SSL_PROTO_TLS1_3
    configuration option) without TLS 1.2 (MBEDTLS_SSL_PROTO_TLS1_2 configuration
    option).

  - TLS 1.2 can be enabled in the build independently of TLS 1.3.

  - If both TLS 1.3 and TLS 1.2 are enabled at build time, only one of them can
    be configured at runtime via `mbedtls_ssl_conf_{min,max}_version`. Otherwise,
    `mbedtls_ssl_setup` will raise `MBEDTLS_ERR_SSL_BAD_CONFIG` error.

- Compatibility with existing SSL/TLS build options:

  The TLS 1.3 MVP is compatible with all TLS 1.2 configuration options in the
  sense that when enabling the TLS 1.3 MVP in the library there is no need to
  modify the configuration for TLS 1.2. The MBEDTLS_USE_PSA_CRYPTO configuration
  option is an exception though, the TLS 1.3 MVP is not compatible with it.

  Mbed TLS SSL/TLS related features are not supported or not applicable to the
  TLS 1.3 MVP:

  | Mbed TLS configuration option            | Support |
  | ---------------------------------------- | ------- |
  | MBEDTLS_SSL_ALL_ALERT_MESSAGES           | no      |
  | MBEDTLS_SSL_ASYNC_PRIVATE                | no      |
  | MBEDTLS_SSL_CONTEXT_SERIALIZATION        | no      |
  | MBEDTLS_SSL_DEBUG_ALL                    | no      |
  | MBEDTLS_SSL_ENCRYPT_THEN_MAC             | n/a     |
  | MBEDTLS_SSL_EXTENDED_MASTER_SECRET       | n/a     |
  | MBEDTLS_SSL_KEEP_PEER_CERTIFICATE        | no      |
  | MBEDTLS_SSL_RENEGOTIATION                | n/a     |
  | MBEDTLS_SSL_MAX_FRAGMENT_LENGTH          | no      |
  |                                          |         |
  | MBEDTLS_SSL_SESSION_TICKETS              | no      |
  | MBEDTLS_SSL_EXPORT_KEYS                  | no (1)  |
  | MBEDTLS_SSL_SERVER_NAME_INDICATION       | no      |
  | MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH       | no      |
  |                                          |         |
  | MBEDTLS_ECP_RESTARTABLE                  | no      |
  | MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED     | no      |
  |                                          |         |
  | MBEDTLS_KEY_EXCHANGE_PSK_ENABLED         | n/a (2) |
  | MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED     | n/a     |
  | MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED   | n/a     |
  | MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED     | n/a     |
  | MBEDTLS_KEY_EXCHANGE_RSA_ENABLED         | n/a     |
  | MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED     | n/a     |
  | MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED   | n/a     |
  | MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED | n/a     |
  | MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED  | n/a     |
  | MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED    | n/a     |
  | MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED     | n/a     |
  |                                          |         |
  | MBEDTLS_USE_PSA_CRYPTO                   | no      |

  (1) Some support has already been upstreamed but it is incomplete.
  (2) Key exchange configuration options for TLS 1.3 will likely to be
      organized around the notion of key exchange mode along the line
      of the MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_NONE/PSK/PSK_EPHEMERAL/EPHEMERAL
      runtime configuration macros.

- Quality considerations
  - Standard Mbed TLS review bar
  - Interoperability testing with OpenSSL and GnuTLS. Test with all the
    cipher suites and signature algorithms supported by OpenSSL/GnuTLS server.
  - Negative testing against OpenSSL/GnuTLS servers with which the
    handshake fails due to incompatibility with the capabilities of the
    MVP: TLS 1.2 or 1.1 server, server sending an HelloRetryRequest message in
    response to the MVP ClientHello, server sending a CertificateRequest
    message ...


Prototype upstreaming status
----------------------------

The following summarizes which parts of the TLS 1.3 prototype remain to be
upstreamed:

- Ephemeral only handshake on client side: client authentication,
  HelloRetryRequest support, version negotiation.

- Ephemeral only handshake server side.

- Pre-shared keys, session resumption and 0-RTT data (both client and server
  side).

- New TLS Message Processing Stack (MPS)

  The TLS 1.3 prototype is developed alongside a rewrite of the TLS messaging layer,
  encompassing low-level details such as record parsing, handshake reassembly, and
  DTLS retransmission state machine.

  MPS has the following components:
  - Layer 1 (Datagram handling)
  - Layer 2 (Record handling)
  - Layer 3 (Message handling)
  - Layer 4 (Retransmission State Machine)
  - Reader  (Abstracted pointer arithmetic and reassembly logic for incoming data)
  - Writer  (Abstracted pointer arithmetic and fragmentation logic for outgoing data)

  Of those components, the following have been upstreamed
  as part of `MBEDTLS_SSL_PROTO_TLS1_3`:

  - Reader ([`library/mps_reader.h`](../../library/mps_reader.h))


Coding rules checklist for TLS 1.3
----------------------------------

The following coding rules are aimed to be a checklist for TLS 1.3 upstreaming
work to reduce review rounds and the number of comments in each round. They
come along (do NOT replace) the project coding rules
(https://tls.mbed.org/kb/development/mbedtls-coding-standards). They have been
established and discussed following the review of #4882 that was the
PR upstreaming the first part of TLS 1.3 ClientHello writing code.

TLS 1.3 specific coding rules:

  - TLS 1.3 specific C modules, headers, static functions names are prefixed
    with `ssl_tls13_`. The same applies to structures and types that are
    internal to C modules.

  - TLS 1.3 specific exported functions, structures and types are
    prefixed with `mbedtls_ssl_tls13_`.

  - Use TLS1_3 in TLS 1.3 specific macros.

  - The names of macros and variables related to a field or structure in the
    TLS 1.3 specification should contain as far as possible the field name as
    it is in the specification. If the field name is "too long" and we prefer
    to introduce some kind of abbreviation of it, use the same abbreviation
    everywhere in the code.

    Example 1: #define CLIENT_HELLO_RANDOM_LEN 32, macro for the length of the
        `random` field of the ClientHello message.

    Example 2 (consistent abbreviation): `mbedtls_ssl_tls13_write_sig_alg_ext()`
        and `MBEDTLS_TLS_EXT_SIG_ALG`, `sig_alg` standing for
        `signature_algorithms`.

  - Regarding vectors that are represented by a length followed by their value
    in the data exchanged between servers and clients:

    - Use `<vector name>_len` for the name of a variable used to compute the
      length in bytes of the vector, where <vector name> is the name of the
      vector as defined in the TLS 1.3 specification.

    - Use `p_<vector_name>_len` for the name of a variable intended to hold
      the address of the first byte of the vector length.

    - Use `<vector_name>` for the name of a variable intended to hold the
      address of the first byte of the vector value.

    - Use `<vector_name>_end` for the name of a variable intended to hold
      the address of the first byte past the vector value.

    Those idioms should lower the risk of mis-using one of the address in place
    of another one which could potentially lead to some nasty issues.

    Example: `cipher_suites` vector of ClientHello in
             `ssl_tls13_write_client_hello_cipher_suites()`
    ```
    size_t cipher_suites_len;
    unsigned char *p_cipher_suites_len;
    unsigned char *cipher_suites;
    ```

  - Where applicable, use:
    - the macros to extract a byte from a multi-byte integer MBEDTLS_BYTE_{0-8}.
    - the macros to write in memory in big-endian order a multi-byte integer
      MBEDTLS_PUT_UINT{8|16|32|64}_BE.
    - the macros to read from memory a multi-byte integer in big-endian order
      MBEDTLS_GET_UINT{8|16|32|64}_BE.
    - the macro to check for space when writing into an output buffer
      `MBEDTLS_SSL_CHK_BUF_PTR`.
    - the macro to check for data when reading from an input buffer
      `MBEDTLS_SSL_CHK_BUF_READ_PTR`.

    These macros were introduced after the prototype was written thus are
    likely not to be used in prototype where we now would use them in
    development.

    The three first types, MBEDTLS_BYTE_{0-8}, MBEDTLS_PUT_UINT{8|16|32|64}_BE
    and MBEDTLS_GET_UINT{8|16|32|64}_BE improve the readability of the code and
    reduce the risk of writing or reading bytes in the wrong order.

    The two last types, `MBEDTLS_SSL_CHK_BUF_PTR` and
    `MBEDTLS_SSL_CHK_BUF_READ_PTR`, improve the readability of the code and
    reduce the risk of error in the non-completely-trivial arithmetic to
    check that we do not write or read past the end of a data buffer. The
    usage of those macros combined with the following rule mitigate the risk
    to read/write past the end of a data buffer.

    Examples:
    ```
    hs_hdr[1] = MBEDTLS_BYTE_2( total_hs_len );
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS, p, 0 );
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 7 );
    ```

  - To mitigate what happened here
    (https://github.com/ARMmbed/mbedtls/pull/4882#discussion_r701704527) from
    happening again, use always a local variable named `p` for the reading
    pointer in functions parsing TLS 1.3 data, and for the writing pointer in
    functions writing data into an output buffer and only that variable. The
    name `p` has been chosen as it was already widely used in TLS code.

  - When an TLS 1.3 structure is written or read by a function or as part of
    a function, provide as documentation the definition of the structure as
    it is in the TLS 1.3 specification.

General coding rules:

  - We prefer grouping "related statement lines" by not adding blank lines
    between them.

    Example 1:
    ```
    ret = ssl_tls13_write_client_hello_cipher_suites( ssl, buf, end, &output_len );
    if( ret != 0 )
        return( ret );
    buf += output_len;
    ```

    Example 2:
    ```
    MBEDTLS_SSL_CHK_BUF_PTR( cipher_suites_iter, end, 2 );
    MBEDTLS_PUT_UINT16_BE( cipher_suite, cipher_suites_iter, 0 );
    cipher_suites_iter += 2;
    ```

  - Use macros for constants that are used in different functions, different
    places in the code. When a constant is used only locally in a function
    (like the length in bytes of the vector lengths in functions reading and
    writing TLS handshake message) there is no need to define a macro for it.

    Example: `#define CLIENT_HELLO_RANDOM_LEN 32`

  - When declaring a pointer the dereferencing operator should be prepended to
    the pointer name not appended to the pointer type:

    Example: `mbedtls_ssl_context *ssl;`

  - Maximum line length is 80 characters.

    Exceptions:

    - string literals can extend beyond 80 characters as we do not want to
      split them to ease their search in the code base.

    - A line can be more than 80 characters by a few characters if just looking
      at the 80 first characters is enough to fully understand the line. For
      example it is generally fine if some closure characters like ";" or ")"
      are beyond the 80 characters limit.

    If a line becomes too long due to a refactoring (for example renaming a
    function to a longer name, or indenting a block more), avoid rewrapping
    lines in the same commit: it makes the review harder. Make one commit with
    the longer lines and another commit with just the rewrapping.

  - When in successive lines, functions and macros parameters should be aligned
    vertically.

    Example:
    ```
    int mbedtls_ssl_start_handshake_msg( mbedtls_ssl_context *ssl,
                                         unsigned hs_type,
                                         unsigned char **buf,
                                         size_t *buf_len );
    ```

  - When a function's parameters span several lines, group related parameters
    together if possible.

    For example, prefer:

    ```
    mbedtls_ssl_start_handshake_msg( ssl, hs_type,
                                     buf, buf_len );
    ```
    over
    ```
    mbedtls_ssl_start_handshake_msg( ssl, hs_type, buf,
                                     buf_len );
    ```
    even if it fits.
