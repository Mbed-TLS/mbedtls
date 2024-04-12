#!/usr/bin/env python3
"""Unit tests for asymmetric_key_data.py
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import re
import subprocess
from typing import Optional
import unittest

# No types :-( https://github.com/wbond/asn1crypto/issues/106
import asn1crypto.core # type: ignore

import scripts_path # pylint: disable=unused-import
from mbedtls_dev.asymmetric_key_data import ASYMMETRIC_KEY_DATA


class ECPrivateKey(asn1crypto.core.Sequence): # SEC1 §C.4 (subset)
    _fields = [
        ('version', asn1crypto.core.Integer),
        ('privateKey', asn1crypto.core.OctetString),
        ('parameters', asn1crypto.core.ObjectIdentifier, {'explicit': 0}),
        ('publicKey', asn1crypto.core.OctetBitString, {'explicit': 1}),
    ]

class RFC8410ObjectIdentifier(asn1crypto.core.ObjectIdentifier):  # RFC 8410 §3
    _map = {
        '1.3.101.110': 'X25519',
        '1.3.101.111': 'X448',
        '1.3.101.112': 'Ed25519',
        '1.3.101.113': 'Ed448',
    }

class AlgorithmIdentifier(asn1crypto.core.Sequence): # RFC 8410 §7 (subset)
    _fields = [
        ('parameters', RFC8410ObjectIdentifier),
    ]

class OneAsymmetricKey(asn1crypto.core.Sequence): # RFC 8410 §7 (subset)
    _fields = [
        ('version', asn1crypto.core.Integer),
        ('privateKeyAlgorithm', AlgorithmIdentifier),
        ('privateKey', asn1crypto.core.OctetString),
        # openssl (as of 3.0) doesn't support bundling the public key
        # with the private key.
    ]

class SubjectPublicKeyInfo(asn1crypto.core.Sequence):
    _fields = [
        ('algorithm', AlgorithmIdentifier),
        ('publicKey', asn1crypto.core.OctetBitString),
    ]

class TestKeyData(unittest.TestCase):
    """Check the key data through unit tests."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # The field maxDiff exists in this parent class, even though
        # for some reason pylint doesn't find it.
        self.maxDiff = None #pylint: disable=invalid-name
        self.openssl = 'openssl'

    def assertBytesEqual(self, #pylint: disable=invalid-name
                         first: bytes, second: bytes,
                         msg: Optional[str] = None) -> None:
        """Assert that two bytes objects are equal.

        In case of failure, show the differences with a hex dump.
        """
        first_hex = first.hex()
        second_hex = second.hex()
        self.assertMultiLineEqual(first_hex, second_hex, msg)

    def check_key_pair(self, pair_der: bytes) -> None:
        """Check that the DER representation of a private key is valid.

        This both performs a slightly loose syntax check (allowing
        multiple formats and trailing garbage) and a validation of the
        correctness and consistency of the internal values (public values
        match private values, etc.).
        """
        check_result = subprocess.check_output(
            [self.openssl, 'pkey', '-inform', 'DER', '-noout', '-check'],
            input=pair_der)
        self.assertEqual(check_result, b'Key is valid\n')

    def check_public_from_private(self, private_der: bytes, public_der: bytes) -> None:
        """Check that the public key is valid and consistent with the private key.

        Both keys must be in a DER format accepted by openssl.
        """
        public_from_openssl = subprocess.check_output(
            [self.openssl, 'pkey', '-inform', 'DER',
             '-outform', 'DER', '-pubout'],
            input=private_der)
        self.assertBytesEqual(public_der, public_from_openssl)

    def ec_weierstrass_get_oid(self, family: str, bits: int) -> bytes:
        """Return the DER encoding of the OID for the specified curve.

        This function only supports curves known to ``openssl ecparam``,
        which excludes Montgomery and Edwards curves.
        """
        bits_for_name = bits
        if family == 'SECP_K1':
            if bits == 224:
                self.fail('PSA uses 225 for the bit-size of secp224k1')
            if bits == 225:
                bits_for_name = 224
        curve_name = re.sub(r'_([a-z][0-9]+)\Z',
                            lambda m: str(bits_for_name) + m.group(1),
                            re.sub(r'brainpool_p', r'brainpoolP',
                                   family.lower()))
        curve_name = {
            'secp192r1': 'prime192v1',
            'secp256r1': 'prime256v1',
        }.get(curve_name, curve_name)
        oid_der = subprocess.check_output(
            [self.openssl, 'ecparam', '-name', curve_name, '-outform', 'DER'])
        return oid_der

    def check_ec_weierstrass_keys(self, family: str, bits: int,
                                  private: bytes, public: bytes) -> None:
        """Check the correctness and consistency of EC Weierstrass keys."""
        oid_der = self.ec_weierstrass_get_oid(family, bits)
        oid_asn1_object = asn1crypto.core.ObjectIdentifier.load(oid_der)
        pair_asn1_object = ECPrivateKey()
        pair_asn1_object['version'] = 1
        pair_asn1_object['parameters'] = oid_asn1_object
        pair_asn1_object['privateKey'] = private
        pair_asn1_object['publicKey'] = public
        pair_der = pair_asn1_object.dump()
        self.check_key_pair(pair_der)

    def check_ec_rfc8410_keys(self, family: str, bits: int,
                              private: bytes, public: bytes) -> None:
        """Check the correctness and consistency of EC Montgomery or Edwards keys."""
        letters = 'X' if family == 'MONTGOMERY' else 'Ed'
        number = '25519' if bits == 255 else str(bits)
        oid_asn1_object = RFC8410ObjectIdentifier(letters + number)
        pka = AlgorithmIdentifier()
        pka['parameters'] = oid_asn1_object

        # Check that the private key is a valid value.
        private_asn1_object = OneAsymmetricKey()
        private_asn1_object['version'] = 0
        private_asn1_object['privateKeyAlgorithm'] = pka
        private_asn1_object['privateKey'] = asn1crypto.core.OctetString(private).dump()
        private_der = private_asn1_object.dump()
        self.check_key_pair(private_der)

        # Check that the public key is correct and consistent with
        # the private key.
        public_asn1_object = SubjectPublicKeyInfo()
        public_asn1_object['algorithm'] = pka
        public_asn1_object['publicKey'] = public
        public_der = public_asn1_object.dump()
        self.check_public_from_private(private_der, public_der)

    def check_rsa_keys(self, bits: int,
                       private: bytes, public: bytes) -> None:
        """Check the correctness and consistency of RSA keys."""
        # Check for strict ASN.1 compliance, including the absence of
        # trailing garbage.
        asn1_dump = subprocess.check_output(
            [self.openssl, 'asn1parse', '-inform', 'DER'],
            input=private).splitlines()
        # Check that we have a SEQUENCE of 9 INTEGERs, which is the
        # concrete syntax of RSAPublicKey.
        self.assertEqual(len(asn1_dump), 10)
        self.assertRegex(asn1_dump[0], br'\A[ 0-9:=a-z]*: SEQUENCE *\Z')
        for line in asn1_dump[1:]:
            self.assertRegex(line, br'\A[ 0-9:=a-z]*: INTEGER *:[0-9A-F]+\Z')
        # Check the key size, which is the bit-size of the modulus.
        modulus_hex = asn1_dump[2].split(b':')[-1]
        self.assertEqual(len(bin(int(modulus_hex, 16))) - 2, bits)

        # Check that the public key is valid and consistent with the private key.
        public_from_openssl = subprocess.check_output(
            [self.openssl, 'rsa', '-inform', 'DER',
             '-outform', 'DER', '-RSAPublicKey_out'],
            input=private)
        self.assertBytesEqual(public, public_from_openssl)

    def check_keys(self, psa_type: str, bits: int,
                   private: bytes, public: bytes) -> None:
        """Check the correctness and consistency of a key pair and a public key."""
        if psa_type == 'PSA_KEY_TYPE_RSA_KEY_PAIR':
            self.check_rsa_keys(bits, private, public)
            return
        m = re.match(r'PSA_KEY_TYPE_ECC_KEY_PAIR\(PSA_ECC_FAMILY_(\w+)\)\Z',
                     psa_type)
        if m:
            family = m.group(1)
            if family in ['MONTGOMERY', 'TWISTED_EDWARDS']:
                self.check_ec_rfc8410_keys(family, bits, private, public)
            else:
                self.check_ec_weierstrass_keys(family, bits, private, public)
            return
        self.fail('Key type not recognized: ' + psa_type)

    def test_key_data(self) -> None:
        """Test the correctness and consistency of the entries of ASYMMETRIC_KEY_DATA."""
        for psa_type, per_type in ASYMMETRIC_KEY_DATA.items():
            if '_KEY_PAIR' in psa_type:
                # If there are private keys of a given type, there must
                # be public keys of the corresponding type.
                public_type = psa_type.replace('_KEY_PAIR', '_PUBLIC_KEY')
                self.assertIn(public_type, ASYMMETRIC_KEY_DATA)
                for bits, private in per_type.items():
                    # If there is a private key of a given type and size,
                    # there must be a public key of the corresponding type
                    # and the same size.
                    self.assertIn(bits, ASYMMETRIC_KEY_DATA[public_type])
                    public = ASYMMETRIC_KEY_DATA[public_type][bits]
                    with self.subTest(type=psa_type, bits=bits):
                        # Check the correctness of consistency of the
                        # private and public keys of a given type and size.
                        self.check_keys(psa_type, bits, private, public)
            elif '_PUBLIC_KEY' in psa_type:
                # If there are public keys of a given type, there must
                # be private keys of the corresponding type.
                pair_type = psa_type.replace('_PUBLIC_KEY', '_KEY_PAIR')
                self.assertIn(pair_type, ASYMMETRIC_KEY_DATA)
                for bits in per_type:
                    # If there is a public key of a given type and size,
                    # there must be a private key of the corresponding type
                    # and the same size.
                    self.assertIn(bits, ASYMMETRIC_KEY_DATA[pair_type])
                    # The correctness of the public key is checked together
                    # with the private key.
            else:
                self.fail('Weird PSA key type: ' + psa_type)


if __name__ == '__main__':
    unittest.main()
