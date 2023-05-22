#!/usr/bin/env python3
from pprint import pprint
import sys
import os
from asn1crypto import pem, x509, crl
from asn1crypto.core import Sequence
from datetime import datetime,timedelta, timezone


class UnhandlePemType:
    def __init__(self, filename,type_name, headers, der_bytes) -> None:
        self._type_name = type_name
        self._headers = headers
        self._der_bytes=der_bytes
        self._filename=filename

    @property
    def filename(self):
        return self._filename

class UnkownFileType:
    def __init__(self, filename):
        self._filename=filename


    @property
    def filename(self):
        return self._filename

def unarmor_pem(filename):
    if not os.path.exists(filename):
        return
    with open(filename, 'rb') as f:
        try:
            for type_name, headers, der_bytes in pem.unarmor(f.read(), multiple=True):

                match type_name:
                    case "CERTIFICATE":
                        yield filename, x509.Certificate.load(der_bytes)
                    case "X509 CRL":
                        yield filename, crl.CertificateList.load(der_bytes)
                    case _:
                        yield UnhandlePemType(filename, type_name, headers, der_bytes)
        except:
            yield UnkownFileType(filename)

def iterate_certs(args):
    for filename in args:
        yield from unarmor_pem(filename)

EXPIRED_CERTS={
    "test-ca2-expired.crt" ,
    "test-int-ca-exp.crt" ,
    "server7-expired.crt",
    "pkcs7-rsa-expired.crt"
}

FURTURE_CERTS={
"server7-future.crt",
}
#  def is_valid_cert(cert : Certificate,check_time=None):
#     check_time=check_time or datetime.now(timezone.utc) + timedelta(days=365*3)
#     if cert.filename in EXPIRED_CERTS:
#         return cert.end < check_time
#     if cert.filename in FURTURE_CERTS:
#         return check_time < cert.start
#     return  cert.start <= check_time <= cert.end
def display_extensions(values,level=0):
    for v in values:
        display(v, level=level)

def display(dict_obj, level=0,indent=2):
    assert isinstance(dict_obj, dict)

    def _print(*args,**kwargs):
        print(' '*(indent*level),*args, sep='',end='',**kwargs )

    for name, value in dict_obj.items():
        # if name == 'extensions':
        #     print(len(value))
        #     for i in value:
        #         print(i)
        match value:
            case dict():
                _print(name,':\n')
                display(value,level=level+1)
            case bytes():
                _print(name,':\n')
                for i in range(0, len(value),16):
                    print(' '*(indent*(level+1)),value[i:i+16].hex())
            case list():
                _print(name,':\n')
                if name == 'extensions':
                    display_extensions(value,level=level+1)
                else:
                    pprint(value)
            case _:
                _print(name,': ', value,' ', type(value),'\n')




def main(args):
    for filename, cert in iterate_certs(args):
        print(filename)
        display(cert.native,indent=2)
    return 0
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
