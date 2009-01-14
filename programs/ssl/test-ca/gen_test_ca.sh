#!/bin/sh
rm -rf index newcerts/*.pem serial *.req *.key *.crt crl.prm

touch index
echo "01" > serial

echo "Generating CA"
openssl req -config sslconf.txt -days 3653 -x509 -newkey rsa:2048 \
            -set_serial 0 -text -keyout test-ca.key -out test-ca.crt

echo "Generating rest"
openssl genrsa -out server1.key 2048
openssl genrsa -out server2.key 2048
openssl genrsa -out client1.key 2048
openssl genrsa -out client2.key 2048

echo "Generating requests"
openssl req -config sslconf.txt -new -key server1.key -out server1.req
openssl req -config sslconf.txt -new -key server2.key -out server2.req
openssl req -config sslconf.txt -new -key client1.key -out client1.req
openssl req -config sslconf.txt -new -key client2.key -out client2.req

echo "Signing requests"
openssl ca -config sslconf.txt -in server1.req -out server1.crt
openssl ca -config sslconf.txt -in server2.req -out server2.crt
openssl ca -config sslconf.txt -in client1.req -out client1.crt
openssl ca -config sslconf.txt -in client2.req -out client2.crt

echo "Revoking firsts"
openssl ca -config sslconf.txt -revoke server1.crt
openssl ca -config sslconf.txt -revoke client1.crt
openssl ca -config sslconf.txt -gencrl -out crl.pem

echo "Verifying second"
openssl x509 -in server2.crt -text -noout
cat test-ca.crt crl.pem > ca_crl.pem
openssl verify -CAfile ca_crl.pem -crl_check server2.crt
rm ca_crl.pem

echo "Generating PKCS12"
openssl pkcs12 -export -in client2.crt -inkey client2.key \
                      -out client2.pfx

rm *.old *.req
