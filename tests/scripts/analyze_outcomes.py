#!/usr/bin/env python3

"""Analyze the test outcomes from a full CI run.

This script can also run on outcomes from a partial run, but the results are
less likely to be useful.
"""

import re
import typing

import scripts_path # pylint: disable=unused-import
from mbedtls_framework import outcome_analysis


class CoverageTask(outcome_analysis.CoverageTask):
    """Justify test cases that are never executed."""

    @staticmethod
    def _has_word_re(words: typing.Iterable[str],
                     exclude: typing.Optional[str] = None) -> typing.Pattern:
        """Construct a regex that matches if any of the words appears.

        The occurrence must start and end at a word boundary.

        If exclude is specified, strings containing a match for that
        regular expression will not match the returned pattern.
        """
        exclude_clause = r''
        if exclude:
            exclude_clause = r'(?!.*' + exclude + ')'
        return re.compile(exclude_clause +
                          r'.*\b(?:' + r'|'.join(words) + r')\b.*',
                          re.DOTALL)

    IGNORED_TESTS = {
        'ssl-opt': [
            # We don't run ssl-opt.sh with Valgrind on the CI because
            # it's extremely slow. We don't intend to change this.
            'DTLS client reconnect from same port: reconnect, nbio, valgrind',
            # We don't have IPv6 in our CI environment.
            # https://github.com/Mbed-TLS/mbedtls-test/issues/176
            'DTLS cookie: enabled, IPv6',
            # Disabled due to OpenSSL bug.
            # https://github.com/openssl/openssl/issues/18887
            'DTLS fragmenting: 3d, openssl client, DTLS 1.2',
            # We don't run ssl-opt.sh with Valgrind on the CI because
            # it's extremely slow. We don't intend to change this.
            'DTLS fragmenting: proxy MTU: auto-reduction (with valgrind)',
            # It seems that we don't run `ssl-opt.sh` with
            # `MBEDTLS_USE_PSA_CRYPTO` enabled but `MBEDTLS_SSL_ASYNC_PRIVATE`
            # disabled.
            # https://github.com/Mbed-TLS/mbedtls/issues/9581
            'Opaque key for server authentication: invalid key: decrypt with ECC key, no async',
            'Opaque key for server authentication: invalid key: ecdh with RSA key, no async',
        ],
        'test_suite_config.mbedtls_boolean': [
            # We never test with CBC/PKCS5/PKCS12 enabled but
            # PKCS7 padding disabled.
            # https://github.com/Mbed-TLS/mbedtls/issues/9580
            'Config: !MBEDTLS_CIPHER_PADDING_PKCS7',
            # https://github.com/Mbed-TLS/mbedtls/issues/9583
            'Config: !MBEDTLS_ECP_NIST_OPTIM',
            # MBEDTLS_ECP_NO_FALLBACK only affects builds using a partial
            # alternative implementation of ECP arithmetic (with
            # MBEDTLS_ECP_INTERNAL_ALT enabled). We don't test those builds.
            # The configuration enumeration script skips xxx_ALT options
            # but not MBEDTLS_ECP_NO_FALLBACK, so it appears in the report,
            # but we don't care about it.
            'Config: MBEDTLS_ECP_NO_FALLBACK',
            # Missing coverage of test configurations.
            # https://github.com/Mbed-TLS/mbedtls/issues/9585
            'Config: !MBEDTLS_SSL_DTLS_ANTI_REPLAY',
            # Missing coverage of test configurations.
            # https://github.com/Mbed-TLS/mbedtls/issues/9585
            'Config: !MBEDTLS_SSL_DTLS_HELLO_VERIFY',
            # We don't run test_suite_config when we test this.
            # https://github.com/Mbed-TLS/mbedtls/issues/9586
            'Config: !MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED',
            # We only test multithreading with pthreads.
            # https://github.com/Mbed-TLS/mbedtls/issues/9584
            'Config: !MBEDTLS_THREADING_PTHREAD',
            # Built but not tested.
            # https://github.com/Mbed-TLS/mbedtls/issues/9587
            'Config: MBEDTLS_AES_USE_HARDWARE_ONLY',
            # Untested platform-specific optimizations.
            # https://github.com/Mbed-TLS/mbedtls/issues/9588
            'Config: MBEDTLS_HAVE_SSE2',
            # Obsolete configuration option, to be replaced by
            # PSA entropy drivers.
            # https://github.com/Mbed-TLS/mbedtls/issues/8150
            'Config: MBEDTLS_NO_PLATFORM_ENTROPY',
            # Untested aspect of the platform interface.
            # https://github.com/Mbed-TLS/mbedtls/issues/9589
            'Config: MBEDTLS_PLATFORM_NO_STD_FUNCTIONS',
            # In a client-server build, test_suite_config runs in the
            # client configuration, so it will never report
            # MBEDTLS_PSA_CRYPTO_SPM as enabled. That's ok.
            'Config: MBEDTLS_PSA_CRYPTO_SPM',
            # We don't test on armv8 yet.
            'Config: MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT',
            'Config: MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY',
            'Config: MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY',
            'Config: MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY',
            # We don't run test_suite_config when we test this.
            # https://github.com/Mbed-TLS/mbedtls/issues/9586
            'Config: MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND',
        ],
        'test_suite_config.psa_boolean': [
            # We don't test with HMAC disabled.
            # https://github.com/Mbed-TLS/mbedtls/issues/9591
            'Config: !PSA_WANT_ALG_HMAC',
            # The DERIVE key type is always enabled.
            'Config: !PSA_WANT_KEY_TYPE_DERIVE',
            # More granularity of key pair type enablement macros
            # than we care to test.
            # https://github.com/Mbed-TLS/mbedtls/issues/9590
            'Config: !PSA_WANT_KEY_TYPE_DH_KEY_PAIR_EXPORT',
            'Config: !PSA_WANT_KEY_TYPE_DH_KEY_PAIR_GENERATE',
            'Config: !PSA_WANT_KEY_TYPE_DH_KEY_PAIR_IMPORT',
            # More granularity of key pair type enablement macros
            # than we care to test.
            # https://github.com/Mbed-TLS/mbedtls/issues/9590
            'Config: !PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT',
            'Config: !PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT',
            # We don't test with HMAC disabled.
            # https://github.com/Mbed-TLS/mbedtls/issues/9591
            'Config: !PSA_WANT_KEY_TYPE_HMAC',
            # The PASSWORD key type is always enabled.
            'Config: !PSA_WANT_KEY_TYPE_PASSWORD',
            # The PASSWORD_HASH key type is always enabled.
            'Config: !PSA_WANT_KEY_TYPE_PASSWORD_HASH',
            # The RAW_DATA key type is always enabled.
            'Config: !PSA_WANT_KEY_TYPE_RAW_DATA',
            # More granularity of key pair type enablement macros
            # than we care to test.
            # https://github.com/Mbed-TLS/mbedtls/issues/9590
            'Config: !PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT',
            'Config: !PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT',
            # Algorithm declared but not supported.
            'Config: PSA_WANT_ALG_CBC_MAC',
            # Algorithm declared but not supported.
            'Config: PSA_WANT_ALG_XTS',
            # Family declared but not supported.
            'Config: PSA_WANT_ECC_SECP_K1_224',
            # More granularity of key pair type enablement macros
            # than we care to test.
            # https://github.com/Mbed-TLS/mbedtls/issues/9590
            'Config: PSA_WANT_KEY_TYPE_DH_KEY_PAIR_DERIVE',
            'Config: PSA_WANT_KEY_TYPE_ECC_KEY_PAIR',
            'Config: PSA_WANT_KEY_TYPE_RSA_KEY_PAIR',
            'Config: PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_DERIVE',
        ],
        'test_suite_config.psa_combinations': [
            # We don't test this unusual, but sensible configuration.
            # https://github.com/Mbed-TLS/mbedtls/issues/9592
            'Config: PSA_WANT_ALG_DETERMINSTIC_ECDSA without PSA_WANT_ALG_ECDSA',
        ],
        'test_suite_pkcs12': [
            # We never test with CBC/PKCS5/PKCS12 enabled but
            # PKCS7 padding disabled.
            # https://github.com/Mbed-TLS/mbedtls/issues/9580
            'PBE Decrypt, (Invalid padding & PKCS7 padding disabled)',
            'PBE Encrypt, pad = 8 (PKCS7 padding disabled)',
        ],
        'test_suite_pkcs5': [
            # We never test with CBC/PKCS5/PKCS12 enabled but
            # PKCS7 padding disabled.
            # https://github.com/Mbed-TLS/mbedtls/issues/9580
            'PBES2 Decrypt (Invalid padding & PKCS7 padding disabled)',
            'PBES2 Encrypt, pad=6 (PKCS7 padding disabled)',
            'PBES2 Encrypt, pad=8 (PKCS7 padding disabled)',
        ],
        'test_suite_psa_crypto': [
            # We don't test this unusual, but sensible configuration.
            # https://github.com/Mbed-TLS/mbedtls/issues/9592
            re.compile(r'.*ECDSA.*only deterministic supported'),
        ],
        'test_suite_psa_crypto_metadata': [
            # Algorithms declared but not supported.
            # https://github.com/Mbed-TLS/mbedtls/issues/9579
            'Asymmetric signature: Ed25519ph',
            'Asymmetric signature: Ed448ph',
            'Asymmetric signature: pure EdDSA',
            'Cipher: XTS',
            'MAC: CBC_MAC-3DES',
            'MAC: CBC_MAC-AES-128',
            'MAC: CBC_MAC-AES-192',
            'MAC: CBC_MAC-AES-256',
        ],
        'test_suite_psa_crypto_not_supported.generated': [
            # We never test with DH key support disabled but support
            # for a DH group enabled. The dependencies of these test
            # cases don't really make sense.
            # https://github.com/Mbed-TLS/mbedtls/issues/9574
            re.compile(r'PSA \w+ DH_.*type not supported'),
            # We only test partial support for DH with the 2048-bit group
            # enabled and the other groups disabled.
            # https://github.com/Mbed-TLS/mbedtls/issues/9575
            'PSA generate DH_KEY_PAIR(RFC7919) 2048-bit group not supported',
            'PSA import DH_KEY_PAIR(RFC7919) 2048-bit group not supported',
            'PSA import DH_PUBLIC_KEY(RFC7919) 2048-bit group not supported',
        ],
        'test_suite_psa_crypto_op_fail.generated': [
            # We don't test this unusual, but sensible configuration.
            # https://github.com/Mbed-TLS/mbedtls/issues/9592
            re.compile(r'.*: !ECDSA but DETERMINISTIC_ECDSA with ECC_.*'),
            # PBKDF2_HMAC is not in the default configuration, so we don't
            # enable it in depends.py where we remove hashes.
            # https://github.com/Mbed-TLS/mbedtls/issues/9576
            re.compile(r'PSA key_derivation PBKDF2_HMAC\(\w+\): !(?!PBKDF2_HMAC\Z).*'),

            # We never test with the HMAC algorithm enabled but the HMAC
            # key type disabled. Those dependencies don't really make sense.
            # https://github.com/Mbed-TLS/mbedtls/issues/9573
            re.compile(r'.* !HMAC with HMAC'),
            # There's something wrong with PSA_WANT_ALG_RSA_PSS_ANY_SALT
            # differing from PSA_WANT_ALG_RSA_PSS.
            # https://github.com/Mbed-TLS/mbedtls/issues/9578
            re.compile(r'PSA sign RSA_PSS_ANY_SALT.*!(?:MD|RIPEMD|SHA).*'),
            # We don't test with ECDH disabled but the key type enabled.
            # https://github.com/Mbed-TLS/TF-PSA-Crypto/issues/161
            re.compile(r'PSA key_agreement.* !ECDH with ECC_KEY_PAIR\(.*'),
            # We don't test with FFDH disabled but the key type enabled.
            # https://github.com/Mbed-TLS/TF-PSA-Crypto/issues/160
            re.compile(r'PSA key_agreement.* !FFDH with DH_KEY_PAIR\(.*'),
        ],
        'test_suite_psa_crypto_op_fail.misc': [
            # We don't test this unusual, but sensible configuration.
            # https://github.com/Mbed-TLS/mbedtls/issues/9592
            'PSA sign DETERMINISTIC_ECDSA(SHA_256): !ECDSA but DETERMINISTIC_ECDSA with ECC_KEY_PAIR(SECP_R1)', #pylint: disable=line-too-long
        ],
        'tls13-misc': [
            # Disabled due to OpenSSL bug.
            # https://github.com/openssl/openssl/issues/10714
            'TLS 1.3 O->m: resumption',
            # Disabled due to OpenSSL command line limitation.
            # https://github.com/Mbed-TLS/mbedtls/issues/9582
            'TLS 1.3 m->O: resumption with early data',
        ],
    }


# The names that we give to classes derived from DriverVSReference do not
# follow the usual naming convention, because it's more readable to use
# underscores and parts of the configuration names. Also, these classes
# are just there to specify some data, so they don't need repetitive
# documentation.
#pylint: disable=invalid-name,missing-class-docstring

class DriverVSReference_hash(outcome_analysis.DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_hash_use_psa'
    DRIVER = 'test_psa_crypto_config_accel_hash_use_psa'
    IGNORED_SUITES = [
        'shax', 'mdx', # the software implementations that are being excluded
        'md.psa',  # purposefully depends on whether drivers are present
        'psa_crypto_low_hash.generated', # testing the builtins
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(MD5|RIPEMD160|SHA[0-9]+)_.*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
    }

class DriverVSReference_hmac(outcome_analysis.DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_hmac'
    DRIVER = 'test_psa_crypto_config_accel_hmac'
    IGNORED_SUITES = [
        # These suites require legacy hash support, which is disabled
        # in the accelerated component.
        'shax', 'mdx',
        # This suite tests builtins directly, but these are missing
        # in the accelerated case.
        'psa_crypto_low_hash.generated',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(MD5|RIPEMD160|SHA[0-9]+)_.*'),
            re.compile(r'.*\bMBEDTLS_MD_C\b')
        ],
        'test_suite_md': [
            # Builtin HMAC is not supported in the accelerate component.
            re.compile('.*HMAC.*'),
            # Following tests make use of functions which are not available
            # when MD_C is disabled, as it happens in the accelerated
            # test component.
            re.compile('generic .* Hash file .*'),
            'MD list',
        ],
        'test_suite_md.psa': [
            # "legacy only" tests require hash algorithms to be NOT
            # accelerated, but this of course false for the accelerated
            # test component.
            re.compile('PSA dispatch .* legacy only'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
    }

class DriverVSReference_cipher_aead_cmac(outcome_analysis.DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_cipher_aead_cmac'
    DRIVER = 'test_psa_crypto_config_accel_cipher_aead_cmac'
    # Modules replaced by drivers.
    IGNORED_SUITES = [
        # low-level (block/stream) cipher modules
        'aes', 'aria', 'camellia', 'des', 'chacha20',
        # AEAD modes and CMAC
        'ccm', 'chachapoly', 'cmac', 'gcm',
        # The Cipher abstraction layer
        'cipher',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(AES|ARIA|CAMELLIA|CHACHA20|DES)_.*'),
            re.compile(r'.*\bMBEDTLS_(CCM|CHACHAPOLY|CMAC|GCM)_.*'),
            re.compile(r'.*\bMBEDTLS_AES(\w+)_C\b.*'),
            re.compile(r'.*\bMBEDTLS_CIPHER_.*'),
        ],
        # PEM decryption is not supported so far.
        # The rest of PEM (write, unencrypted read) works though.
        'test_suite_pem': [
            re.compile(r'PEM read .*(AES|DES|\bencrypt).*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
        # Following tests depend on AES_C/DES_C but are not about
        # them really, just need to know some error code is there.
        'test_suite_error': [
            'Low and high error',
            'Single low error'
        ],
        # Similar to test_suite_error above.
        'test_suite_version': [
            'Check for MBEDTLS_AES_C when already present',
        ],
        # The en/decryption part of PKCS#12 is not supported so far.
        # The rest of PKCS#12 (key derivation) works though.
        'test_suite_pkcs12': [
            re.compile(r'PBE Encrypt, .*'),
            re.compile(r'PBE Decrypt, .*'),
        ],
        # The en/decryption part of PKCS#5 is not supported so far.
        # The rest of PKCS#5 (PBKDF2) works though.
        'test_suite_pkcs5': [
            re.compile(r'PBES2 Encrypt, .*'),
            re.compile(r'PBES2 Decrypt .*'),
        ],
        # Encrypted keys are not supported so far.
        # pylint: disable=line-too-long
        'test_suite_pkparse': [
            'Key ASN1 (Encrypted key PKCS12, trailing garbage data)',
            'Key ASN1 (Encrypted key PKCS5, trailing garbage data)',
            re.compile(r'Parse (RSA|EC) Key .*\(.* ([Ee]ncrypted|password).*\)'),
        ],
        # Encrypted keys are not supported so far.
        'ssl-opt': [
            'TLS: password protected server key',
            'TLS: password protected client key',
            'TLS: password protected server key, two certificates',
        ],
    }

class DriverVSReference_ecp_light_only(outcome_analysis.DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_ecc_ecp_light_only'
    DRIVER = 'test_psa_crypto_config_accel_ecc_ecp_light_only'
    IGNORED_SUITES = [
        # Modules replaced by drivers
        'ecdsa', 'ecdh', 'ecjpake',
        # Unit tests for the built-in implementation
        'psa_crypto_ecp',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(ECDH|ECDSA|ECJPAKE|ECP)_.*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
        # This test wants a legacy function that takes f_rng, p_rng
        # arguments, and uses legacy ECDSA for that. The test is
        # really about the wrapper around the PSA RNG, not ECDSA.
        'test_suite_random': [
            'PSA classic wrapper: ECDSA signature (SECP256R1)',
        ],
        # In the accelerated test ECP_C is not set (only ECP_LIGHT is)
        # so we must ignore disparities in the tests for which ECP_C
        # is required.
        'test_suite_ecp': [
            re.compile(r'ECP check public-private .*'),
            re.compile(r'ECP calculate public: .*'),
            re.compile(r'ECP gen keypair .*'),
            re.compile(r'ECP point muladd .*'),
            re.compile(r'ECP point multiplication .*'),
            re.compile(r'ECP test vectors .*'),
        ],
        'test_suite_ssl': [
            # This deprecated function is only present when ECP_C is On.
            'Test configuration of EC groups through mbedtls_ssl_conf_curves()',
        ],
    }

class DriverVSReference_no_ecp_at_all(outcome_analysis.DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_ecc_no_ecp_at_all'
    DRIVER = 'test_psa_crypto_config_accel_ecc_no_ecp_at_all'
    IGNORED_SUITES = [
        # Modules replaced by drivers
        'ecp', 'ecdsa', 'ecdh', 'ecjpake',
        # Unit tests for the built-in implementation
        'psa_crypto_ecp',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(ECDH|ECDSA|ECJPAKE|ECP)_.*'),
            re.compile(r'.*\bMBEDTLS_PK_PARSE_EC_COMPRESSED\b.*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
        # See ecp_light_only
        'test_suite_random': [
            'PSA classic wrapper: ECDSA signature (SECP256R1)',
        ],
        'test_suite_pkparse': [
            # When PK_PARSE_C and ECP_C are defined then PK_PARSE_EC_COMPRESSED
            # is automatically enabled in build_info.h (backward compatibility)
            # even if it is disabled in config_psa_crypto_no_ecp_at_all(). As a
            # consequence compressed points are supported in the reference
            # component but not in the accelerated one, so they should be skipped
            # while checking driver's coverage.
            re.compile(r'Parse EC Key .*compressed\)'),
            re.compile(r'Parse Public EC Key .*compressed\)'),
        ],
        # See ecp_light_only
        'test_suite_ssl': [
            'Test configuration of EC groups through mbedtls_ssl_conf_curves()',
        ],
    }

class DriverVSReference_ecc_no_bignum(outcome_analysis.DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_ecc_no_bignum'
    DRIVER = 'test_psa_crypto_config_accel_ecc_no_bignum'
    IGNORED_SUITES = [
        # Modules replaced by drivers
        'ecp', 'ecdsa', 'ecdh', 'ecjpake',
        'bignum_core', 'bignum_random', 'bignum_mod', 'bignum_mod_raw',
        'bignum.generated', 'bignum.misc',
        # Unit tests for the built-in implementation
        'psa_crypto_ecp',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_BIGNUM_C\b.*'),
            re.compile(r'.*\bMBEDTLS_(ECDH|ECDSA|ECJPAKE|ECP)_.*'),
            re.compile(r'.*\bMBEDTLS_PK_PARSE_EC_COMPRESSED\b.*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
        # See ecp_light_only
        'test_suite_random': [
            'PSA classic wrapper: ECDSA signature (SECP256R1)',
        ],
        # See no_ecp_at_all
        'test_suite_pkparse': [
            re.compile(r'Parse EC Key .*compressed\)'),
            re.compile(r'Parse Public EC Key .*compressed\)'),
        ],
        'test_suite_asn1parse': [
            'INTEGER too large for mpi',
        ],
        'test_suite_asn1write': [
            re.compile(r'ASN.1 Write mpi.*'),
        ],
        'test_suite_debug': [
            re.compile(r'Debug print mbedtls_mpi.*'),
        ],
        # See ecp_light_only
        'test_suite_ssl': [
            'Test configuration of EC groups through mbedtls_ssl_conf_curves()',
        ],
    }

class DriverVSReference_ecc_ffdh_no_bignum(outcome_analysis.DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_ecc_ffdh_no_bignum'
    DRIVER = 'test_psa_crypto_config_accel_ecc_ffdh_no_bignum'
    IGNORED_SUITES = [
        # Modules replaced by drivers
        'ecp', 'ecdsa', 'ecdh', 'ecjpake', 'dhm',
        'bignum_core', 'bignum_random', 'bignum_mod', 'bignum_mod_raw',
        'bignum.generated', 'bignum.misc',
        # Unit tests for the built-in implementation
        'psa_crypto_ecp',
    ]
    IGNORED_TESTS = {
        'ssl-opt': [
            # DHE support in TLS 1.2 requires built-in MBEDTLS_DHM_C
            # (because it needs custom groups, which PSA does not
            # provide), even with MBEDTLS_USE_PSA_CRYPTO.
            re.compile(r'PSK callback:.*\bdhe-psk\b.*'),
        ],
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_BIGNUM_C\b.*'),
            re.compile(r'.*\bMBEDTLS_DHM_C\b.*'),
            re.compile(r'.*\bMBEDTLS_(ECDH|ECDSA|ECJPAKE|ECP)_.*'),
            re.compile(r'.*\bMBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED\b.*'),
            re.compile(r'.*\bMBEDTLS_PK_PARSE_EC_COMPRESSED\b.*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
        # See ecp_light_only
        'test_suite_random': [
            'PSA classic wrapper: ECDSA signature (SECP256R1)',
        ],
        # See no_ecp_at_all
        'test_suite_pkparse': [
            re.compile(r'Parse EC Key .*compressed\)'),
            re.compile(r'Parse Public EC Key .*compressed\)'),
        ],
        'test_suite_asn1parse': [
            'INTEGER too large for mpi',
        ],
        'test_suite_asn1write': [
            re.compile(r'ASN.1 Write mpi.*'),
        ],
        'test_suite_debug': [
            re.compile(r'Debug print mbedtls_mpi.*'),
        ],
        # See ecp_light_only
        'test_suite_ssl': [
            'Test configuration of EC groups through mbedtls_ssl_conf_curves()',
        ],
    }

class DriverVSReference_ffdh_alg(outcome_analysis.DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_ffdh'
    DRIVER = 'test_psa_crypto_config_accel_ffdh'
    IGNORED_SUITES = ['dhm']
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_DHM_C\b.*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
    }

class DriverVSReference_tfm_config(outcome_analysis.DriverVSReference):
    REFERENCE = 'test_tfm_config_no_p256m'
    DRIVER = 'test_tfm_config_p256m_driver_accel_ec'
    IGNORED_SUITES = [
        # Modules replaced by drivers
        'asn1parse', 'asn1write',
        'ecp', 'ecdsa', 'ecdh', 'ecjpake',
        'bignum_core', 'bignum_random', 'bignum_mod', 'bignum_mod_raw',
        'bignum.generated', 'bignum.misc',
        # Unit tests for the built-in implementation
        'psa_crypto_ecp',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_BIGNUM_C\b.*'),
            re.compile(r'.*\bMBEDTLS_(ASN1\w+)_C\b.*'),
            re.compile(r'.*\bMBEDTLS_(ECDH|ECDSA|ECP)_.*'),
            re.compile(r'.*\bMBEDTLS_PSA_P256M_DRIVER_ENABLED\b.*')
        ],
        'test_suite_config.crypto_combinations': [
            'Config: ECC: Weierstrass curves only',
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
        # See ecp_light_only
        'test_suite_random': [
            'PSA classic wrapper: ECDSA signature (SECP256R1)',
        ],
    }

class DriverVSReference_rsa(outcome_analysis.DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_rsa_crypto'
    DRIVER = 'test_psa_crypto_config_accel_rsa_crypto'
    IGNORED_SUITES = [
        # Modules replaced by drivers.
        'rsa', 'pkcs1_v15', 'pkcs1_v21',
        # We temporarily don't care about PK stuff.
        'pk', 'pkwrite', 'pkparse'
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(PKCS1|RSA)_.*'),
            re.compile(r'.*\bMBEDTLS_GENPRIME\b.*')
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
        # Following tests depend on RSA_C but are not about
        # them really, just need to know some error code is there.
        'test_suite_error': [
            'Low and high error',
            'Single high error'
        ],
        # Constant time operations only used for PKCS1_V15
        'test_suite_constant_time': [
            re.compile(r'mbedtls_ct_zeroize_if .*'),
            re.compile(r'mbedtls_ct_memmove_left .*')
        ],
        'test_suite_psa_crypto': [
            # We don't support generate_key_custom entry points
            # in drivers yet.
            re.compile(r'PSA generate key custom: RSA, e=.*'),
            re.compile(r'PSA generate key ext: RSA, e=.*'),
        ],
    }

class DriverVSReference_block_cipher_dispatch(outcome_analysis.DriverVSReference):
    REFERENCE = 'test_full_block_cipher_legacy_dispatch'
    DRIVER = 'test_full_block_cipher_psa_dispatch'
    IGNORED_SUITES = [
        # Skipped in the accelerated component
        'aes', 'aria', 'camellia',
        # These require AES_C, ARIA_C or CAMELLIA_C to be enabled in
        # order for the cipher module (actually cipher_wrapper) to work
        # properly. However these symbols are disabled in the accelerated
        # component so we ignore them.
        'cipher.ccm', 'cipher.gcm', 'cipher.aes', 'cipher.aria',
        'cipher.camellia',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(AES|ARIA|CAMELLIA)_.*'),
            re.compile(r'.*\bMBEDTLS_AES(\w+)_C\b.*'),
        ],
        'test_suite_cmac': [
            # Following tests require AES_C/ARIA_C/CAMELLIA_C to be enabled,
            # but these are not available in the accelerated component.
            'CMAC null arguments',
            re.compile('CMAC.* (AES|ARIA|Camellia).*'),
        ],
        'test_suite_cipher.padding': [
            # Following tests require AES_C/CAMELLIA_C to be enabled,
            # but these are not available in the accelerated component.
            re.compile('Set( non-existent)? padding with (AES|CAMELLIA).*'),
        ],
        'test_suite_pkcs5': [
            # The AES part of PKCS#5 PBES2 is not yet supported.
            # The rest of PKCS#5 (PBKDF2) works, though.
            re.compile(r'PBES2 .* AES-.*')
        ],
        'test_suite_pkparse': [
            # PEM (called by pkparse) requires AES_C in order to decrypt
            # the key, but this is not available in the accelerated
            # component.
            re.compile('Parse RSA Key.*(password|AES-).*'),
        ],
        'test_suite_pem': [
            # Following tests require AES_C, but this is diabled in the
            # accelerated component.
            re.compile('PEM read .*AES.*'),
            'PEM read (unknown encryption algorithm)',
        ],
        'test_suite_error': [
            # Following tests depend on AES_C but are not about them
            # really, just need to know some error code is there.
            'Single low error',
            'Low and high error',
        ],
        'test_suite_version': [
            # Similar to test_suite_error above.
            'Check for MBEDTLS_AES_C when already present',
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
    }

#pylint: enable=invalid-name,missing-class-docstring


# List of tasks with a function that can handle this task and additional arguments if required
KNOWN_TASKS = {
    'analyze_coverage': CoverageTask,
    'analyze_driver_vs_reference_hash': DriverVSReference_hash,
    'analyze_driver_vs_reference_hmac': DriverVSReference_hmac,
    'analyze_driver_vs_reference_cipher_aead_cmac': DriverVSReference_cipher_aead_cmac,
    'analyze_driver_vs_reference_ecp_light_only': DriverVSReference_ecp_light_only,
    'analyze_driver_vs_reference_no_ecp_at_all': DriverVSReference_no_ecp_at_all,
    'analyze_driver_vs_reference_ecc_no_bignum': DriverVSReference_ecc_no_bignum,
    'analyze_driver_vs_reference_ecc_ffdh_no_bignum': DriverVSReference_ecc_ffdh_no_bignum,
    'analyze_driver_vs_reference_ffdh_alg': DriverVSReference_ffdh_alg,
    'analyze_driver_vs_reference_tfm_config': DriverVSReference_tfm_config,
    'analyze_driver_vs_reference_rsa': DriverVSReference_rsa,
    'analyze_block_cipher_dispatch': DriverVSReference_block_cipher_dispatch,
}

if __name__ == '__main__':
    outcome_analysis.main(KNOWN_TASKS)
