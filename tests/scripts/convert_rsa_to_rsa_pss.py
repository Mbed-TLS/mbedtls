#!/usr/bin/env python3

from collections import OrderedDict
import sys
from asn1crypto import pem,keys

RSAPSS_PARAM=OrderedDict([('algorithm', 'rsassa_pss'),
             ('parameters',
              OrderedDict([('hash_algorithm',
                            OrderedDict([('algorithm', sys.argv[3]),
                                         ('parameters', None)])),
                           ('mask_gen_algorithm',
                            OrderedDict([('algorithm', 'mgf1'),
                                         ('parameters',
                                          OrderedDict([('algorithm', sys.argv[3]),
                                                       ('parameters',
                                                        None)]))])),
                           ('salt_length', int(sys.argv[4], 0)),
                           ('trailer_field', 'trailer_field_bc')]))])
import base64
# coded_string = '''Q5YACgA...'''

coded_string='''
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDA3zf8F7vglp0/
ht6WMn1EpRagzSHxmdTs6st8GFgIlKXsm8WL3xoemTiZhx57wI053zhdcHgH057Z
k+i5clHFzqMwUqny50BwFMtEonILwuVA+T7lpg6z+exKY8C4KQB0nFc7qKUEkHHx
vYPZP9al4jwqj+8nYMPGn8u67GB9t+aEMr5P+1gmIgNb1LTV+/Xjli5wwOQuvfwu
7uJBVcA0Ln0kcmnLR7EUQIN9Z/SG9jGr8XmksrUuEvmEF/Bibyc+E1ixVA0hmnM3
oTDPb5Lc9un8rNsuKNF+AksjoBXyOGVkCeoMbo4bF6BxyLObyavpw/LPh5aPgAIy
nplYb6LVAgMBAAECggEAP/cH0zRv28k3t4TcN0XhY624tnWxxzW0dypbd/l+4MGj
0bfLqVrBh9pa+hfk1TgD3miYgey18iqN6SzzpuUyF38zgeg4ctWc+k77JvUVC6+E
ZqsC4BjVkXzWj8lLdggrHYFoMOH6cGwTThADNT7FylggiiEYOKAP7cS7RW/1hFuw
z06dWBNrNTVpodLE8sFIBCBRuWukXaVLhIhDSJksu6SX1tYY9uxc0TFJyfKPC03v
CQL+ff27ryuDlCLEpz5m9eBX3PLtLD6BdHYelm90HjIOFDHQdPD0B73D0SLCqJWS
Bn9DApG83SMBiZQgRGT1HWfSj+hppSkl5lCc4+nLdQKBgQDiKT6qa9VZHpzmR9W2
1+Pxjp7pg18Qn2PsBETMP/jZOhfgT/7YTc1GVHS/CsRnnKfYiWVM/VgqRw/0N7ZV
sB3tpzn8T6PEdTqjmKdF9WbLfGX7gCPm//2ZH45r/16TZt9sb8P2OC7/abWsrrvG
cRZr0Pgi2fiiciDS4jpwS96rLwKBgQDaUZu4sioUdVhAjSdw+jFIsCAhNPpMV6gR
iPOnriHptivRzaf42AyKdiI1RM4/JSmDfXmnMdbssr/aNLb2sjvzeFoEgzM+ouKB
ghPUNRdjm57EjZFMA3fHcVvug23VeIj2LHnCSrR5kHC/3zRWlnHjDmiRvOrLM8C+
Rdf8MP0BOwKBgQDSnyq3OBnHF5VzeK71y3WDfxlLy4b7ShWathcESQeN9mZKBvYF
p99mgjz/th1XiTNfnAV1f/Nd3DRlcoUipBQbQcPk0J5p1es4dHBD3NlQ5Jdtc9b7
yKf6tMLEnV0M1Z95s1TCt2w9fcst+MTzeFozKrgMbQb68mLTQtC9yEqlDQKBgQDU
qZAV3r8sxI2d+6HC5IPjeWUi07dJbE2UHyKxYOc6ALE4oqsPtGyq554043xAeFOy
+SPqoJrqYMiPpq/fKQlLBh4xrRfa2NHpM6tbGAhbh/ilH/273Njtl1fkw3PW8J4B
pptIjnq0u+WIkcUq30u60Is+A5d3L0d+UQyuZY3ehwKBgCAkD9Kvwig7lyCykknr
CWhAsr7Rw4OUNDjWyew0CflBbVxClPcE/DI5abwc+z5hmMCA2DZHw23CLueBKhc0
ZDBOlrsmFrlBNv6K1lN8quw5QlDv47MBKDLKbfWaHp83vv44ICKRjM2VAvJNbxq0
Q/AZ32XAkuedLwnn7Gmowo8N
'''
print(base64.b64decode(coded_string))
with open(sys.argv[1],'wb') as outf, open(sys.argv[2],'rb') as inf:
    _,_,der_bytes=pem.unarmor(inf.read())
    key_info=keys.PrivateKeyInfo.load(der_bytes).native
    key_info['private_key_algorithm']=RSAPSS_PARAM
    outf.write(pem.armor('PRIVATE KEY', keys.PrivateKeyInfo(key_info).dump()))

