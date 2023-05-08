#!/usr/bin/env python3
from pprint import pprint
import sys
import os
from asn1crypto import pem, x509, crl
from asn1crypto.core import Sequence
from datetime import datetime,timedelta, timezone

class Certificate:
    def __init__(self, filename, cert) -> None:
        self._cert=cert
        self._filename=filename
        assert isinstance(cert, (x509.Certificate,crl.CertificateList))
        match cert:
            case x509.Certificate():
                self._start=cert.not_valid_before
                self._end=cert.not_valid_after
                self._type='x509'
            case crl.CertificateList():
                self._start=cert['tbs_cert_list']['this_update'].native
                self._end=cert['tbs_cert_list']['next_update'].native
                self._type='crl'

    @property
    def start(self):
        return self._start

    @property
    def end(self):
        return self._end

    @property
    def type(self):
        return self._type

    @property
    def filename(self):
        return self._filename

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
                        yield Certificate(filename, x509.Certificate.load(der_bytes))
                    case "X509 CRL":
                        yield Certificate(filename, crl.CertificateList.load(der_bytes))
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
def is_valid_cert(cert : Certificate,check_time=None):
    check_time=check_time or datetime.now(timezone.utc) + timedelta(days=365*3)
    if cert.filename in EXPIRED_CERTS:
        return cert.end < check_time
    if cert.filename in FURTURE_CERTS:
        return check_time < cert.start
    return  cert.start <= check_time <= cert.end

def main(args):
    for cert in iterate_certs(args):
        if not isinstance(cert, Certificate) or is_valid_cert(cert):
            continue
        print(cert.filename,cert.type,is_valid_cert(cert),cert.start, cert.end)
    return 0
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))