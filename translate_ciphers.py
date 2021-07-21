import re

def translate_gnu(m_cipher):
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
        index=m_cipher.rindex("-")
        m_cipher = m_cipher[:index]+":+"+m_cipher[index+1:]
        m_cipher = re.sub(r"GCM\:\+SHA\d\d\d", "GCM:+AEAD", m_cipher)

    return m_cipher

def translate_ossl(m_cipher):
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
        m_cipher=m_cipher[:index+8]

    # If DES is being used, Replace DHE with EDH
    if "DES" in m_cipher and "DHE" in m_cipher and "ECDHE" not in m_cipher:
        m_cipher = m_cipher.replace("DHE", "EDH")

    return m_cipher
