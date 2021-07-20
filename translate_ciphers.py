
def translate_gnu(m_cipher):

    m_cipher = "+" + m_cipher[4:]
    m_cipher = m_cipher.replace("-WITH-", ":+")
    m_cipher = m_cipher.replace("-EDE", "")
    if m_cipher.split("-")[-1] == "SHA":
        m_cipher = m_cipher+"1"
    
    
    if m_cipher.split("-")[-1] == "8" or m_cipher.split("-")[-1] == "CCM":
        m_cipher = m_cipher+":+AEAD"
    else:
        index=m_cipher.rindex("-")
        m_cipher = m_cipher[:index]+":+"+m_cipher[index+1:]
        m_cipher = m_cipher.replace("GCM:+SHA256", "GCM:+AEAD")
        m_cipher = m_cipher.replace("GCM:+SHA384", "GCM:+AEAD")

    return m_cipher
    
def translate_ossl(m_cipher):
    m_cipher = m_cipher[4:]
    m_cipher = m_cipher.replace("-WITH", "")
    m_cipher = m_cipher.replace("AES-", "AES")
    m_cipher = m_cipher.replace("CAMELLIA-", "CAMELLIA")
    m_cipher = m_cipher.replace("ARIA-", "ARIA")
        
    m_cipher = m_cipher.replace("-EDE", "")

    m_cipher = m_cipher.replace("3DES-CBC", "DES-CBC3")
    try:
        index = m_cipher.rindex("CBC")
        if m_cipher[index-4:index-1] != "DES":
            m_cipher = m_cipher.replace("CBC-", "")
    except:
        pass

    if m_cipher[:4] == "RSA-":
        m_cipher = m_cipher[4:]

    m_cipher = m_cipher.replace("ECDHE-RSA-ARIA", "ECDHE-ARIA")

    try:
        index = m_cipher.rindex("POLY1305")
        m_cipher=m_cipher[:index+8]
    except Exception as e:
        pass#print(e)

    return m_cipher

def test_all_common():
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
        #"EDH-RSA-DES-CBC3-SHA",
        "DHE-RSA-DES-CBC3-SHA",
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

        #"PSK-3DES-EDE-CBC-SHA",
        #"PSK-AES128-CBC-SHA",
        #"PSK-AES256-CBC-SHA",

        "PSK-DES-CBC3-SHA",
        "PSK-AES128-SHA",
        "PSK-AES256-SHA",
    ]
    
    for i in range(len(m_ciphers)):

        g = translate_gnu(m_ciphers[i])
        if g!=g_ciphers[i]:
            print("GNU", i)
            print("new".ljust(10), g)
            print("original".ljust(10), g_ciphers[i])
        #    break

        
        o = translate_ossl(m_ciphers[i])
        if o!=o_ciphers[i]:
            print("OpenSSL", i)
            print("new".ljust(10), o)
            print("original".ljust(10), o_ciphers[i])
        #    break
        
def test_mbed_ossl_common():
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
        #"EDH-RSA-DES-CBC-SHA",
        "DHE-RSA-DES-CBC-SHA",

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

    for i in range(len(m_ciphers)):

        o = translate_ossl(m_ciphers[i])
        if o!=o_ciphers[i]:
            print("OpenSSL", i)
            print("new".ljust(10), o)
            print("original".ljust(10), o_ciphers[i])
        #    break

def test_mbed_gnu_common():
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

    for i in range(len(m_ciphers)):

        g = translate_gnu(m_ciphers[i])
        if g!=g_ciphers[i]:
            print("GNU", i)
            print("new".ljust(10), g)
            print("original".ljust(10), g_ciphers[i])
        #    break

test_all_common()
test_mbed_ossl_common()
test_mbed_gnu_common()