#!/usr/bin/env python3

# test_translate_ciphers_names.py
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Test translate_ciphers.py by running every MBedTLS ciphersuite name
combination through the translate functions and comparing them to their
correct GNUTLS or OpenSSL counterpart.
"""

from translate_ciphers import translate_gnutls, translate_ossl

def assert_equal(translate, original):
    """
    Compare the translated ciphersuite name against the original
    On fail, print the mismatch on the screen to directly compare the
    differences
    """
    try:
        assert translate == original
    except AssertionError:
        print("%s\n%s\n" %(translate, original))

def test_all_common():
    """
    Translate the MBedTLS ciphersuite names to the common OpenSSL and
    GnuTLS ciphersite names, and compare them with the true, expected
    corresponding OpenSSL and GnuTLS ciphersuite names
    """
    m_ciphers = [
        "TLS-ECDHE-ECDSA-WITH-NULL-SHA",
        "TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA",
        "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA",
        "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA",

        "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256",
        "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384",
        "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256",
        "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384",

        "TLS-DHE-RSA-WITH-AES-128-CBC-SHA",
        "TLS-DHE-RSA-WITH-AES-256-CBC-SHA",
        "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA",
        "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA",
        "TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA",
        "TLS-RSA-WITH-AES-256-CBC-SHA",
        "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA",
        "TLS-RSA-WITH-AES-128-CBC-SHA",
        "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA",
        "TLS-RSA-WITH-3DES-EDE-CBC-SHA",
        "TLS-RSA-WITH-NULL-MD5",
        "TLS-RSA-WITH-NULL-SHA",

        "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA",
        "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA",
        "TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA",
        "TLS-ECDHE-RSA-WITH-NULL-SHA",

        "TLS-RSA-WITH-AES-128-CBC-SHA256",
        "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256",
        "TLS-RSA-WITH-AES-256-CBC-SHA256",
        "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256",
        "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256",
        "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384",
        "TLS-RSA-WITH-AES-128-GCM-SHA256",
        "TLS-RSA-WITH-AES-256-GCM-SHA384",
        "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256",
        "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384",
        "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256",
        "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384",

        "TLS-PSK-WITH-3DES-EDE-CBC-SHA",
        "TLS-PSK-WITH-AES-128-CBC-SHA",
        "TLS-PSK-WITH-AES-256-CBC-SHA",
    ]
    g_ciphers = [
        "+ECDHE-ECDSA:+NULL:+SHA1",
        "+ECDHE-ECDSA:+3DES-CBC:+SHA1",
        "+ECDHE-ECDSA:+AES-128-CBC:+SHA1",
        "+ECDHE-ECDSA:+AES-256-CBC:+SHA1",

        "+ECDHE-ECDSA:+AES-128-CBC:+SHA256",
        "+ECDHE-ECDSA:+AES-256-CBC:+SHA384",
        "+ECDHE-ECDSA:+AES-128-GCM:+AEAD",
        "+ECDHE-ECDSA:+AES-256-GCM:+AEAD",

        "+DHE-RSA:+AES-128-CBC:+SHA1",
        "+DHE-RSA:+AES-256-CBC:+SHA1",
        "+DHE-RSA:+CAMELLIA-128-CBC:+SHA1",
        "+DHE-RSA:+CAMELLIA-256-CBC:+SHA1",
        "+DHE-RSA:+3DES-CBC:+SHA1",
        "+RSA:+AES-256-CBC:+SHA1",
        "+RSA:+CAMELLIA-256-CBC:+SHA1",
        "+RSA:+AES-128-CBC:+SHA1",
        "+RSA:+CAMELLIA-128-CBC:+SHA1",
        "+RSA:+3DES-CBC:+SHA1",
        "+RSA:+NULL:+MD5",
        "+RSA:+NULL:+SHA1",

        "+ECDHE-RSA:+AES-128-CBC:+SHA1",
        "+ECDHE-RSA:+AES-256-CBC:+SHA1",
        "+ECDHE-RSA:+3DES-CBC:+SHA1",
        "+ECDHE-RSA:+NULL:+SHA1",

        "+RSA:+AES-128-CBC:+SHA256",
        "+DHE-RSA:+AES-128-CBC:+SHA256",
        "+RSA:+AES-256-CBC:+SHA256",
        "+DHE-RSA:+AES-256-CBC:+SHA256",
        "+ECDHE-RSA:+AES-128-CBC:+SHA256",
        "+ECDHE-RSA:+AES-256-CBC:+SHA384",
        "+RSA:+AES-128-GCM:+AEAD",
        "+RSA:+AES-256-GCM:+AEAD",
        "+DHE-RSA:+AES-128-GCM:+AEAD",
        "+DHE-RSA:+AES-256-GCM:+AEAD",
        "+ECDHE-RSA:+AES-128-GCM:+AEAD",
        "+ECDHE-RSA:+AES-256-GCM:+AEAD",

        "+PSK:+3DES-CBC:+SHA1",
        "+PSK:+AES-128-CBC:+SHA1",
        "+PSK:+AES-256-CBC:+SHA1",
    ]
    o_ciphers = [
        "ECDHE-ECDSA-NULL-SHA",
        "ECDHE-ECDSA-DES-CBC3-SHA",
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-ECDSA-AES256-SHA",

        "ECDHE-ECDSA-AES128-SHA256",
        "ECDHE-ECDSA-AES256-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",

        "DHE-RSA-AES128-SHA",
        "DHE-RSA-AES256-SHA",
        "DHE-RSA-CAMELLIA128-SHA",
        "DHE-RSA-CAMELLIA256-SHA",
        "EDH-RSA-DES-CBC3-SHA",
        "AES256-SHA",
        "CAMELLIA256-SHA",
        "AES128-SHA",
        "CAMELLIA128-SHA",
        "DES-CBC3-SHA",
        "NULL-MD5",
        "NULL-SHA",

        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-RSA-DES-CBC3-SHA",
        "ECDHE-RSA-NULL-SHA",

        #"NULL-SHA256",
        "AES128-SHA256",
        "DHE-RSA-AES128-SHA256",
        "AES256-SHA256",
        "DHE-RSA-AES256-SHA256",
        "ECDHE-RSA-AES128-SHA256",
        "ECDHE-RSA-AES256-SHA384",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",

        "PSK-3DES-EDE-CBC-SHA",
        "PSK-AES128-CBC-SHA",
        "PSK-AES256-CBC-SHA",
    ]

    for i, m_cipher in enumerate(m_ciphers):

        g = translate_gnutls(m_cipher)
        assert_equal(g, g_ciphers[i])

        o = translate_ossl(m_cipher)
        assert_equal(o, o_ciphers[i])

def test_mbedtls_ossl_common():
    """
    Translate the MBedTLS ciphersuite names to the common OpenSSL
    ciphersite names, and compare them with the true, expected
    corresponding OpenSSL ciphersuite name
    """
    m_ciphers = [
        "TLS-ECDH-ECDSA-WITH-NULL-SHA",
        "TLS-ECDH-ECDSA-WITH-3DES-EDE-CBC-SHA",
        "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA",
        "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA",

        "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256",
        "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA384",
        "TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256",
        "TLS-ECDH-ECDSA-WITH-AES-256-GCM-SHA384",
        "TLS-ECDHE-ECDSA-WITH-ARIA-256-GCM-SHA384",
        "TLS-ECDHE-ECDSA-WITH-ARIA-128-GCM-SHA256",
        "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256",

        "TLS-RSA-WITH-DES-CBC-SHA",
        "TLS-DHE-RSA-WITH-DES-CBC-SHA",

        "TLS-ECDHE-RSA-WITH-ARIA-256-GCM-SHA384",
        "TLS-DHE-RSA-WITH-ARIA-256-GCM-SHA384",
        "TLS-RSA-WITH-ARIA-256-GCM-SHA384",
        "TLS-ECDHE-RSA-WITH-ARIA-128-GCM-SHA256",
        "TLS-DHE-RSA-WITH-ARIA-128-GCM-SHA256",
        "TLS-RSA-WITH-ARIA-128-GCM-SHA256",
        "TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256",
        "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256",

        "TLS-DHE-PSK-WITH-ARIA-256-GCM-SHA384",
        "TLS-DHE-PSK-WITH-ARIA-128-GCM-SHA256",
        "TLS-PSK-WITH-ARIA-256-GCM-SHA384",
        "TLS-PSK-WITH-ARIA-128-GCM-SHA256",
        "TLS-PSK-WITH-CHACHA20-POLY1305-SHA256",
        "TLS-ECDHE-PSK-WITH-CHACHA20-POLY1305-SHA256",
        "TLS-DHE-PSK-WITH-CHACHA20-POLY1305-SHA256",
    ]
    o_ciphers = [
        "ECDH-ECDSA-NULL-SHA",
        "ECDH-ECDSA-DES-CBC3-SHA",
        "ECDH-ECDSA-AES128-SHA",
        "ECDH-ECDSA-AES256-SHA",

        "ECDH-ECDSA-AES128-SHA256",
        "ECDH-ECDSA-AES256-SHA384",
        "ECDH-ECDSA-AES128-GCM-SHA256",
        "ECDH-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-ARIA256-GCM-SHA384",
        "ECDHE-ECDSA-ARIA128-GCM-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305",

        "DES-CBC-SHA",
        "EDH-RSA-DES-CBC-SHA",

        "ECDHE-ARIA256-GCM-SHA384",
        "DHE-RSA-ARIA256-GCM-SHA384",
        "ARIA256-GCM-SHA384",
        "ECDHE-ARIA128-GCM-SHA256",
        "DHE-RSA-ARIA128-GCM-SHA256",
        "ARIA128-GCM-SHA256",
        "DHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",

        "DHE-PSK-ARIA256-GCM-SHA384",
        "DHE-PSK-ARIA128-GCM-SHA256",
        "PSK-ARIA256-GCM-SHA384",
        "PSK-ARIA128-GCM-SHA256",
        "PSK-CHACHA20-POLY1305",
        "ECDHE-PSK-CHACHA20-POLY1305",
        "DHE-PSK-CHACHA20-POLY1305",
    ]

    for i, m_cipher in enumerate(m_ciphers):

        o = translate_ossl(m_cipher)
        assert_equal(o, o_ciphers[i])

def test_mbedtls_gnutls_common():
    """
    Translate the MBedTLS ciphersuite names to the common GnuTLS
    ciphersite names, and compare them with the true, expected
    corresponding GnuTLS ciphersuite names
    """
    m_ciphers = [
        "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256",
        "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA384",
        "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-GCM-SHA256",
        "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-GCM-SHA384",
        "TLS-ECDHE-ECDSA-WITH-AES-128-CCM",
        "TLS-ECDHE-ECDSA-WITH-AES-256-CCM",
        "TLS-ECDHE-ECDSA-WITH-AES-128-CCM-8",
        "TLS-ECDHE-ECDSA-WITH-AES-256-CCM-8",

        "TLS-RSA-WITH-NULL-SHA256",

        "TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256",
        "TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA384",
        "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256",
        "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256",
        "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256",
        "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256",
        "TLS-ECDHE-RSA-WITH-CAMELLIA-128-GCM-SHA256",
        "TLS-ECDHE-RSA-WITH-CAMELLIA-256-GCM-SHA384",
        "TLS-DHE-RSA-WITH-CAMELLIA-128-GCM-SHA256",
        "TLS-DHE-RSA-WITH-CAMELLIA-256-GCM-SHA384",
        "TLS-RSA-WITH-CAMELLIA-128-GCM-SHA256",
        "TLS-RSA-WITH-CAMELLIA-256-GCM-SHA384",
        "TLS-RSA-WITH-AES-128-CCM",
        "TLS-RSA-WITH-AES-256-CCM",
        "TLS-DHE-RSA-WITH-AES-128-CCM",
        "TLS-DHE-RSA-WITH-AES-256-CCM",
        "TLS-RSA-WITH-AES-128-CCM-8",
        "TLS-RSA-WITH-AES-256-CCM-8",
        "TLS-DHE-RSA-WITH-AES-128-CCM-8",
        "TLS-DHE-RSA-WITH-AES-256-CCM-8",

        "TLS-DHE-PSK-WITH-3DES-EDE-CBC-SHA",
        "TLS-DHE-PSK-WITH-AES-128-CBC-SHA",
        "TLS-DHE-PSK-WITH-AES-256-CBC-SHA",

        "TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA",
        "TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA",
        "TLS-ECDHE-PSK-WITH-3DES-EDE-CBC-SHA",
        "TLS-RSA-PSK-WITH-3DES-EDE-CBC-SHA",
        "TLS-RSA-PSK-WITH-AES-256-CBC-SHA",
        "TLS-RSA-PSK-WITH-AES-128-CBC-SHA",

        "TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA384",
        "TLS-ECDHE-PSK-WITH-CAMELLIA-256-CBC-SHA384",
        "TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA256",
        "TLS-ECDHE-PSK-WITH-CAMELLIA-128-CBC-SHA256",
        "TLS-ECDHE-PSK-WITH-NULL-SHA384",
        "TLS-ECDHE-PSK-WITH-NULL-SHA256",
        "TLS-PSK-WITH-AES-128-CBC-SHA256",
        "TLS-PSK-WITH-AES-256-CBC-SHA384",
        "TLS-DHE-PSK-WITH-AES-128-CBC-SHA256",
        "TLS-DHE-PSK-WITH-AES-256-CBC-SHA384",
        "TLS-PSK-WITH-NULL-SHA256",
        "TLS-PSK-WITH-NULL-SHA384",
        "TLS-DHE-PSK-WITH-NULL-SHA256",
        "TLS-DHE-PSK-WITH-NULL-SHA384",
        "TLS-RSA-PSK-WITH-AES-256-CBC-SHA384",
        "TLS-RSA-PSK-WITH-AES-128-CBC-SHA256",
        "TLS-RSA-PSK-WITH-NULL-SHA256",
        "TLS-RSA-PSK-WITH-NULL-SHA384",
        "TLS-DHE-PSK-WITH-CAMELLIA-128-CBC-SHA256",
        "TLS-DHE-PSK-WITH-CAMELLIA-256-CBC-SHA384",
        "TLS-PSK-WITH-CAMELLIA-128-CBC-SHA256",
        "TLS-PSK-WITH-CAMELLIA-256-CBC-SHA384",
        "TLS-RSA-PSK-WITH-CAMELLIA-256-CBC-SHA384",
        "TLS-RSA-PSK-WITH-CAMELLIA-128-CBC-SHA256",
        "TLS-PSK-WITH-AES-128-GCM-SHA256",
        "TLS-PSK-WITH-AES-256-GCM-SHA384",
        "TLS-DHE-PSK-WITH-AES-128-GCM-SHA256",
        "TLS-DHE-PSK-WITH-AES-256-GCM-SHA384",
        "TLS-PSK-WITH-AES-128-CCM",
        "TLS-PSK-WITH-AES-256-CCM",
        "TLS-DHE-PSK-WITH-AES-128-CCM",
        "TLS-DHE-PSK-WITH-AES-256-CCM",
        "TLS-PSK-WITH-AES-128-CCM-8",
        "TLS-PSK-WITH-AES-256-CCM-8",
        "TLS-DHE-PSK-WITH-AES-128-CCM-8",
        "TLS-DHE-PSK-WITH-AES-256-CCM-8",
        "TLS-RSA-PSK-WITH-CAMELLIA-128-GCM-SHA256",
        "TLS-RSA-PSK-WITH-CAMELLIA-256-GCM-SHA384",
        "TLS-PSK-WITH-CAMELLIA-128-GCM-SHA256",
        "TLS-PSK-WITH-CAMELLIA-256-GCM-SHA384",
        "TLS-DHE-PSK-WITH-CAMELLIA-128-GCM-SHA256",
        "TLS-DHE-PSK-WITH-CAMELLIA-256-GCM-SHA384",
        "TLS-RSA-PSK-WITH-AES-256-GCM-SHA384",
        "TLS-RSA-PSK-WITH-AES-128-GCM-SHA256",
    ]
    g_ciphers = [
        "+ECDHE-ECDSA:+CAMELLIA-128-CBC:+SHA256",
        "+ECDHE-ECDSA:+CAMELLIA-256-CBC:+SHA384",
        "+ECDHE-ECDSA:+CAMELLIA-128-GCM:+AEAD",
        "+ECDHE-ECDSA:+CAMELLIA-256-GCM:+AEAD",
        "+ECDHE-ECDSA:+AES-128-CCM:+AEAD",
        "+ECDHE-ECDSA:+AES-256-CCM:+AEAD",
        "+ECDHE-ECDSA:+AES-128-CCM-8:+AEAD",
        "+ECDHE-ECDSA:+AES-256-CCM-8:+AEAD",

        "+RSA:+NULL:+SHA256",

        "+ECDHE-RSA:+CAMELLIA-128-CBC:+SHA256",
        "+ECDHE-RSA:+CAMELLIA-256-CBC:+SHA384",
        "+RSA:+CAMELLIA-128-CBC:+SHA256",
        "+RSA:+CAMELLIA-256-CBC:+SHA256",
        "+DHE-RSA:+CAMELLIA-128-CBC:+SHA256",
        "+DHE-RSA:+CAMELLIA-256-CBC:+SHA256",
        "+ECDHE-RSA:+CAMELLIA-128-GCM:+AEAD",
        "+ECDHE-RSA:+CAMELLIA-256-GCM:+AEAD",
        "+DHE-RSA:+CAMELLIA-128-GCM:+AEAD",
        "+DHE-RSA:+CAMELLIA-256-GCM:+AEAD",
        "+RSA:+CAMELLIA-128-GCM:+AEAD",
        "+RSA:+CAMELLIA-256-GCM:+AEAD",
        "+RSA:+AES-128-CCM:+AEAD",
        "+RSA:+AES-256-CCM:+AEAD",
        "+DHE-RSA:+AES-128-CCM:+AEAD",
        "+DHE-RSA:+AES-256-CCM:+AEAD",
        "+RSA:+AES-128-CCM-8:+AEAD",
        "+RSA:+AES-256-CCM-8:+AEAD",
        "+DHE-RSA:+AES-128-CCM-8:+AEAD",
        "+DHE-RSA:+AES-256-CCM-8:+AEAD",

        "+DHE-PSK:+3DES-CBC:+SHA1",
        "+DHE-PSK:+AES-128-CBC:+SHA1",
        "+DHE-PSK:+AES-256-CBC:+SHA1",

        "+ECDHE-PSK:+AES-256-CBC:+SHA1",
        "+ECDHE-PSK:+AES-128-CBC:+SHA1",
        "+ECDHE-PSK:+3DES-CBC:+SHA1",
        "+RSA-PSK:+3DES-CBC:+SHA1",
        "+RSA-PSK:+AES-256-CBC:+SHA1",
        "+RSA-PSK:+AES-128-CBC:+SHA1",

        "+ECDHE-PSK:+AES-256-CBC:+SHA384",
        "+ECDHE-PSK:+CAMELLIA-256-CBC:+SHA384",
        "+ECDHE-PSK:+AES-128-CBC:+SHA256",
        "+ECDHE-PSK:+CAMELLIA-128-CBC:+SHA256",
        "+ECDHE-PSK:+NULL:+SHA384",
        "+ECDHE-PSK:+NULL:+SHA256",
        "+PSK:+AES-128-CBC:+SHA256",
        "+PSK:+AES-256-CBC:+SHA384",
        "+DHE-PSK:+AES-128-CBC:+SHA256",
        "+DHE-PSK:+AES-256-CBC:+SHA384",
        "+PSK:+NULL:+SHA256",
        "+PSK:+NULL:+SHA384",
        "+DHE-PSK:+NULL:+SHA256",
        "+DHE-PSK:+NULL:+SHA384",
        "+RSA-PSK:+AES-256-CBC:+SHA384",
        "+RSA-PSK:+AES-128-CBC:+SHA256",
        "+RSA-PSK:+NULL:+SHA256",
        "+RSA-PSK:+NULL:+SHA384",
        "+DHE-PSK:+CAMELLIA-128-CBC:+SHA256",
        "+DHE-PSK:+CAMELLIA-256-CBC:+SHA384",
        "+PSK:+CAMELLIA-128-CBC:+SHA256",
        "+PSK:+CAMELLIA-256-CBC:+SHA384",
        "+RSA-PSK:+CAMELLIA-256-CBC:+SHA384",
        "+RSA-PSK:+CAMELLIA-128-CBC:+SHA256",
        "+PSK:+AES-128-GCM:+AEAD",
        "+PSK:+AES-256-GCM:+AEAD",
        "+DHE-PSK:+AES-128-GCM:+AEAD",
        "+DHE-PSK:+AES-256-GCM:+AEAD",
        "+PSK:+AES-128-CCM:+AEAD",
        "+PSK:+AES-256-CCM:+AEAD",
        "+DHE-PSK:+AES-128-CCM:+AEAD",
        "+DHE-PSK:+AES-256-CCM:+AEAD",
        "+PSK:+AES-128-CCM-8:+AEAD",
        "+PSK:+AES-256-CCM-8:+AEAD",
        "+DHE-PSK:+AES-128-CCM-8:+AEAD",
        "+DHE-PSK:+AES-256-CCM-8:+AEAD",
        "+RSA-PSK:+CAMELLIA-128-GCM:+AEAD",
        "+RSA-PSK:+CAMELLIA-256-GCM:+AEAD",
        "+PSK:+CAMELLIA-128-GCM:+AEAD",
        "+PSK:+CAMELLIA-256-GCM:+AEAD",
        "+DHE-PSK:+CAMELLIA-128-GCM:+AEAD",
        "+DHE-PSK:+CAMELLIA-256-GCM:+AEAD",
        "+RSA-PSK:+AES-256-GCM:+AEAD",
        "+RSA-PSK:+AES-128-GCM:+AEAD",
    ]

    for i, m_ciphers in enumerate(m_ciphers):

        g = translate_gnutls(m_ciphers)
        assert_equal(g, g_ciphers[i])

test_all_common()
test_mbedtls_ossl_common()
test_mbedtls_gnutls_common()
