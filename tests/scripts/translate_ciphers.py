#!/usr/bin/env python3

# translate_ciphers.py
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

"""
Translate ciphersuite names in MBedTLS format to OpenSSL and GNUTLS
standards.

Format and analyse strings past in via input arguments to match
the expected strings utilised in compat.sh.

sys.argv[1] should be "g" or "o" for GNUTLS or OpenSSL.
sys.argv[2] should be a string containing one or more ciphersuite names.
"""

import re
import sys

def translate_gnutls(m_cipher):
    """
    Translate m_cipher from MBedTLS ciphersuite naming convention
    and return the GnuTLS naming convention
    """

    # Remove "TLS-"
    # Replace "-WITH-" with ":+"
    # Remove "EDE"
    m_cipher = "+" + m_cipher[4:]
    m_cipher = m_cipher.replace("-WITH-", ":+")
    m_cipher = m_cipher.replace("-EDE", "")

    # SHA == SHA1, if the last 3 chars are SHA append 1
    if m_cipher[-3:] == "SHA":
        m_cipher = m_cipher+"1"

    # CCM or CCM-8 should be followed by ":+AEAD"
    if "CCM" in m_cipher:
        m_cipher = m_cipher+":+AEAD"

    # Replace the last "-" with ":+"
    # Replace "GCM:+SHAxyz" with "GCM:+AEAD"
    else:
        index = m_cipher.rindex("-")
        m_cipher = m_cipher[:index]+":+"+m_cipher[index+1:]
        m_cipher = re.sub(r"GCM\:\+SHA\d\d\d", "GCM:+AEAD", m_cipher)

    return m_cipher

def translate_ossl(m_cipher):
    """
    Translate m_cipher from MBedTLS ciphersuite naming convention
    and return the OpenSSL naming convention
    """

    # Remove "TLS-"
    # Remove "WITH"
    m_cipher = m_cipher[4:]
    m_cipher = m_cipher.replace("-WITH", "")

    # Remove the "-" from "ABC-xyz"
    m_cipher = m_cipher.replace("AES-", "AES")
    m_cipher = m_cipher.replace("CAMELLIA-", "CAMELLIA")
    m_cipher = m_cipher.replace("ARIA-", "ARIA")

    # Remove "RSA" if it is at the beginning
    if m_cipher[:4] == "RSA-":
        m_cipher = m_cipher[4:]

    # For all circumstances outside of PSK
    if "PSK" not in m_cipher:
        m_cipher = m_cipher.replace("-EDE", "")
        m_cipher = m_cipher.replace("3DES-CBC", "DES-CBC3")

        # Remove "CBC" if it is not prefixed by DES
        if "CBC" in m_cipher:
            index = m_cipher.rindex("CBC")
            if m_cipher[index-4:index-1] != "DES":
                m_cipher = m_cipher.replace("CBC-", "")

    # ECDHE-RSA-ARIA does not exist in OpenSSL
    m_cipher = m_cipher.replace("ECDHE-RSA-ARIA", "ECDHE-ARIA")

    # POLY1305 should not be followed by anything
    if "POLY1305" in m_cipher:
        index = m_cipher.rindex("POLY1305")
        m_cipher = m_cipher[:index+8]

    # If DES is being used, Replace DHE with EDH
    if "DES" in m_cipher and "DHE" in m_cipher and "ECDHE" not in m_cipher:
        m_cipher = m_cipher.replace("DHE", "EDH")

    return m_cipher

def format_ciphersuite_names(mode, ciphers):
    try:
        t = {"g": translate_gnutls, "o": translate_ossl}[mode]
        return " ".join(t(c) for c in ciphers.split())
    except (KeyError) as e:
        print(e)
        print("Incorrect use of argument 1, should be either \"g\" or \"o\"")
        sys.exit(1)

def main():
    if len(sys.argv) != 3:
        print("""Incorrect number of arguments.
The first argument with either an \"o\" for OpenSSL or \"g\" for GNUTLS.
The second argument should a single space seperated string of MBedTLS ciphersuite names""")
        sys.exit(1)
    print(format_ciphersuite_names(sys.argv[1], sys.argv[2]))
    sys.exit(0)

if __name__ == "__main__":
    main()
