## Reporting Vulnerabilities

If you think you have found an Mbed TLS security vulnerability, then please
send an email to the security team at
<mbed-tls-security@lists.trustedfirmware.org>.

## Security Incident Handling Process

Our security process is detailed in our
[security
center](https://developer.trustedfirmware.org/w/mbed-tls/security-center/).

Its primary goal is to ensure fixes are ready to be deployed when the issue
goes public.

## Maintained branches

Only the maintained branches, as listed in [`BRANCHES.md`](BRANCHES.md),
get security fixes.
Users are urged to always use the latest version of a maintained branch.

## Threat model

We use the following classification of attacks:

- **Remote Attacks:** The attacker can observe and modify data sent over the
  network. This includes observing timing of individual packets and potentially
  delaying legitimate messages.
- **Timing Attacks:** The attacker can gain information about the time taken
  by certain sets of instructions in Mbed TLS operations.
- **Physical Attacks:** The attacker has access to physical information about
  the hardware Mbed TLS is running on and/or can alter the physical state of
  the hardware.

### Remote attacks

Mbed TLS aims to fully protect against remote attacks. Mbed Crypto aims to
enable the user application in providing full protection against remote
attacks. Said protection is limited to providing security guarantees offered by
the protocol in question. (For example Mbed TLS alone won't guarantee that the
messages will arrive without delay, as the TLS protocol doesn't guarantee that
either.)

### Timing attacks

Mbed TLS and Mbed Crypto provide limited protection against timing attacks. The
cost of protecting against timing attacks widely varies depending on the
granularity of the measurements and the noise present. Therefore the protection
in Mbed TLS and Mbed Crypto is limited. We are only aiming to provide protection
against publicly documented attacks, and this protection is not currently complete.

**Warning!** Block ciphers do not yet achieve full protection. For
details and workarounds see the section below.

#### Block Ciphers

Currently there are four block ciphers in Mbed TLS: AES, CAMELLIA, ARIA and DES.
The Mbed TLS implementation uses lookup tables, which are vulnerable to timing
attacks.

**Workarounds:**

- Turn on hardware acceleration for AES. This is supported only on selected
  architectures and currently only available for AES. See configuration options
  `MBEDTLS_AESCE_C`, `MBEDTLS_AESNI_C` and `MBEDTLS_PADLOCK_C` for details.
- Add a secure alternative implementation (typically a bitsliced implementation or
  hardware acceleration) for the vulnerable cipher. See the [Alternative
Implementations Guide](docs/architecture/alternative-implementations.md) for
  more information.
- Instead of a block cipher, use ChaCha20/Poly1305 for encryption and data
  origin authentication.

### Physical attacks

Physical attacks are out of scope. Any attack using information about or
influencing the physical state of the hardware is considered physical,
independently of the attack vector. (For example Row Hammer and Screaming
Channels are considered physical attacks.) If physical attacks are present in a
use case or a user application's threat model, it needs to be mitigated by
physical countermeasures.
