#!/bin/sh
. "${0%/*}/../demo_common.sh"

msg <<'EOF'
This script demonstrates the use of x509 tools to generate a certificate
for a private key. It shows both the case of a self-signed certificate and
the case of a certificate signed by a different key using a certificate
signing request.
EOF

depends_on MBEDTLS_CTR_DRBG_C MBEDTLS_ENTROPY_C MBEDTLS_ERROR_C MBEDTLS_FS_IO MBEDTLS_PEM_WRITE_C MBEDTLS_PK_PARSE_C MBEDTLS_PK_WRITE_C MBEDTLS_SHA256_C MBEDTLS_X509_CRT_PARSE_C MBEDTLS_X509_CRT_WRITE_C MBEDTLS_X509_CSR_PARSE_C MBEDTLS_X509_CSR_WRITE_C

ca_key="demo_ca.key"
server_key="demo_server.key"
csr="demo_csr.req"
ca_crt="demo_ca.crt"
server_crt="demo_server.crt"

files_to_clean="$ca_key $server_key $csr $ca_crt $server_crt"

run 'Generate a CA (certificate authority) key.' \
    "$programs_dir/pkey/gen_key" filename="$ca_key" type=ec

run 'Self-sign the CA certificate.' \
    "$programs_dir/x509/cert_write" issuer_key="$ca_key" output_file="$ca_crt" \
                                    selfsign=1 is_ca=1 \
                                    issuer_name="CN=Demo CA,O=Mbed TLS,C=UK"

run 'The CA certificate is:' \
    cat "$ca_crt"

run 'Dump of the CA certificate:' \
    "$programs_dir/x509/cert_app" mode=file filename="$ca_crt"

run 'Generate a server key.' \
    "$programs_dir/pkey/gen_key" filename="$server_key" type=ec

run 'Issue a signing request for the server key.' \
    "$programs_dir/x509/cert_req" filename="$server_key" output_file="$csr" \
                                  subject_name="CN=Demo server,O=Mbed TLS,C=UK"

run 'Show information about the certificate signing request' \
    "$programs_dir/x509/req_app" filename="$csr"

run 'The CA signs the server key.' \
    "$programs_dir/x509/cert_write" issuer_key="$ca_key" request_file="$csr" \
                                    output_file="$server_crt"

run 'The server certificate is:' \
    cat "$server_crt"

run 'Dump of the server certificate:' \
    "$programs_dir/x509/cert_app" mode=file filename="$server_crt"

cleanup
