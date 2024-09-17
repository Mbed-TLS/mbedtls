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
    # We'll populate IGNORED_TESTS soon. In the meantime, lack of coverage
    # is just a warning.
    outcome_analysis.FULL_COVERAGE_BY_DEFAULT = False

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
                          re.S)

    # generate_psa_tests.py generates test cases involving cryptographic
    # mechanisms (key types, families, algorithms) that are declared but
    # not implemented. Until we improve the Python scripts, ignore those
    # test cases in the analysis.
    # https://github.com/Mbed-TLS/mbedtls/issues/9572
    _PSA_MECHANISMS_NOT_IMPLEMENTED = [
        r'CBC_MAC',
        r'DETERMINISTIC_DSA',
        r'DET_DSA',
        r'DSA',
        r'ECC_KEY_PAIR\(BRAINPOOL_P_R1\) (?:160|192|224|320)-bit',
        r'ECC_KEY_PAIR\(SECP_K1\) 225-bit',
        r'ECC_PAIR\(BP_R1\) (?:160|192|224|320)-bit',
        r'ECC_PAIR\(SECP_K1\) 225-bit',
        r'ECC_PUBLIC_KEY\(BRAINPOOL_P_R1\) (?:160|192|224|320)-bit',
        r'ECC_PUBLIC_KEY\(SECP_K1\) 225-bit',
        r'ECC_PUB\(BP_R1\) (?:160|192|224|320)-bit',
        r'ECC_PUB\(SECP_K1\) 225-bit',
        r'ED25519PH',
        r'ED448PH',
        r'PEPPER',
        r'PURE_EDDSA',
        r'SECP_R2',
        r'SECT_K1',
        r'SECT_R1',
        r'SECT_R2',
        r'SHAKE256_512',
        r'SHA_512_224',
        r'SHA_512_256',
        r'TWISTED_EDWARDS',
        r'XTS',
    ]
    PSA_MECHANISM_NOT_IMPLEMENTED_SEARCH_RE = \
        _has_word_re(_PSA_MECHANISMS_NOT_IMPLEMENTED)

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
        'test_suite_pkcs12': [
            # Probably a missing configuration in the CI.
            # https://github.com/Mbed-TLS/mbedtls/issues/9580
            'PBE Decrypt, (Invalid padding & PKCS7 padding disabled)',
            'PBE Encrypt, pad = 8 (PKCS7 padding disabled)',
        ],
        'test_suite_pkcs5': [
            # Probably a missing configuration in the CI.
            # https://github.com/Mbed-TLS/mbedtls/issues/9580
            'PBES2 Decrypt (Invalid padding & PKCS7 padding disabled)',
            'PBES2 Encrypt, pad=6 (PKCS7 padding disabled)',
            'PBES2 Encrypt, pad=8 (PKCS7 padding disabled)',
        ],
        'test_suite_psa_crypto_generate_key.generated': [
            # Ignore mechanisms that are not implemented, except
            # for public keys for which we always test that
            # psa_generate_key() returns PSA_ERROR_INVALID_ARGUMENT
            # regardless of whether the specific key type is supported.
            _has_word_re((mech
                          for mech in _PSA_MECHANISMS_NOT_IMPLEMENTED
                          if not mech.startswith('ECC_PUB')),
                         exclude=r'ECC_PUB'),
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
            # It is a bug that not-supported test cases aren't getting
            # run for never-implemented key types.
            # https://github.com/Mbed-TLS/mbedtls/issues/7915
            PSA_MECHANISM_NOT_IMPLEMENTED_SEARCH_RE,
            # We mever test with DH key support disabled but support
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
            # Ignore mechanisms that are not implemented, except
            # for test cases that assume the mechanism is not supported.
            _has_word_re(_PSA_MECHANISMS_NOT_IMPLEMENTED,
                         exclude=(r'.*: !(?:' +
                                  r'|'.join(_PSA_MECHANISMS_NOT_IMPLEMENTED) +
                                  r')\b')),
            # Incorrect dependency generation. To be fixed as part of the
            # resolution of https://github.com/Mbed-TLS/mbedtls/issues/9167
            # by forward-porting the commit
            # "PSA test case generation: dependency inference class: operation fail"
            # from https://github.com/Mbed-TLS/mbedtls/pull/9025 .
            re.compile(r'.* with (?:DH|ECC)_(?:KEY_PAIR|PUBLIC_KEY)\(.*'),
            # PBKDF2_HMAC is not in the default configuration, so we don't
            # enable it in depends.py where we remove hashes.
            # https://github.com/Mbed-TLS/mbedtls/issues/9576
            re.compile(r'PSA key_derivation PBKDF2_HMAC\(\w+\): !(?!PBKDF2_HMAC\Z).*'),
            # We never test with TLS12_PRF or TLS12_PSK_TO_MS disabled
            # but certain other things enabled.
            # https://github.com/Mbed-TLS/mbedtls/issues/9577
            re.compile(r'PSA key_derivation TLS12_PRF\(\w+\): !TLS12_PRF'),
            re.compile(r'PSA key_derivation TLS12_PSK_TO_MS'
                       r'\((?!SHA_256|SHA_384|SHA_512)\w+\): !TLS12_PSK_TO_MS'),
            'PSA key_derivation KEY_AGREEMENT(ECDH,TLS12_PRF(SHA_256)): !TLS12_PRF',
            'PSA key_derivation KEY_AGREEMENT(ECDH,TLS12_PRF(SHA_384)): !TLS12_PRF',

            # We never test with the HMAC algorithm enabled but the HMAC
            # key type disabled. Those dependencies don't really make sense.
            # https://github.com/Mbed-TLS/mbedtls/issues/9573
            re.compile(r'.* !HMAC with HMAC'),
            # There's something wrong with PSA_WANT_ALG_RSA_PSS_ANY_SALT
            # differing from PSA_WANT_ALG_RSA_PSS.
            # https://github.com/Mbed-TLS/mbedtls/issues/9578
            re.compile(r'PSA sign RSA_PSS_ANY_SALT.*!(?:MD|RIPEMD|SHA).*'),
        ],
        'test_suite_psa_crypto_storage_format.current': [
            PSA_MECHANISM_NOT_IMPLEMENTED_SEARCH_RE,
        ],
        'test_suite_psa_crypto_storage_format.v0': [
            PSA_MECHANISM_NOT_IMPLEMENTED_SEARCH_RE,
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
            'Test configuration of groups for DHE through mbedtls_ssl_conf_curves()',
        ],
    }

class DriverVSReference_no_ecp_at_all(outcome_analysis.DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_ecc_no_ecp_at_all'
    DRIVER = 'test_psa_crypto_config_accel_ecc_no_ecp_at_all'
    IGNORED_SUITES = [
        # Modules replaced by drivers
        'ecp', 'ecdsa', 'ecdh', 'ecjpake',
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
            'Test configuration of groups for DHE through mbedtls_ssl_conf_curves()',
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
            'Test configuration of groups for DHE through mbedtls_ssl_conf_curves()',
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
            'Test configuration of groups for DHE through mbedtls_ssl_conf_curves()',
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
