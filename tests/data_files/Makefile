## This file contains a record of how some of the test data was
## generated. The final build products are committed to the repository
## as well to make sure that the test data is identical. You do not
## need to use this makefile unless you're extending mbed TLS's tests.

## Many data files were generated prior to the existence of this
## makefile, so the method of their generation was not recorded.

## Note that in addition to depending on the version of the data
## generation tool, many of the build outputs are randomized, so
## running this makefile twice would not produce the same results.

## Tools
OPENSSL ?= openssl
FAKETIME ?= faketime

## Build the generated test data. Note that since the final outputs
## are committed to the repository, this target should do nothing on a
## fresh checkout. Furthermore, since the generation is randomized,
## re-running the same targets may result in differing files. The goal
## of this makefile is primarily to serve as a record of how the
## targets were generated in the first place.
default: all_final

all_intermediate := # temporary files
all_final := # files used by tests



################################################################
#### Generate certificates from existing keys
################################################################

test_ca_key_file_rsa = test-ca.key
test_ca_pwd_rsa = PolarSSLTest
test_ca_config_file = test-ca.opensslconf

test-ca.csr: $(test_ca_key_file_rsa) $(test_ca_config_file)
	$(OPENSSL) req -new -config $(test_ca_config_file) -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -subj "/C=NL/O=PolarSSL/CN=PolarSSL Test CA" -out $@
all_intermediate += test-ca.csr
test-ca-sha1.crt: $(test_ca_key_file_rsa) $(test_ca_config_file) test-ca.csr
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 0 -days 3653 -sha1 -in test-ca.csr -out $@
all_final += test-ca-sha1.crt
test-ca-sha256.crt: $(test_ca_key_file_rsa) $(test_ca_config_file) test-ca.csr
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 0 -days 3653 -sha256 -in test-ca.csr -out $@
all_final += test-ca-sha256.crt

cli_crt_key_file_rsa = cli-rsa.key
cli_crt_extensions_file = cli.opensslconf

cli-rsa.csr: $(cli_crt_key_file_rsa)
	$(OPENSSL) req -new -key $(cli_crt_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -subj "/C=NL/O=PolarSSL/CN=PolarSSL Client 2" -out $@
all_intermediate += cli-rsa.csr
cli-rsa-sha1.crt: $(cli_crt_key_file_rsa) test-ca-sha1.crt cli-rsa.csr
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa -CA test-ca-sha1.crt -CAkey $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 4 -days 3653 -sha1 -in cli-rsa.csr -out $@
all_final += cli-rsa-sha1.crt
cli-rsa-sha256.crt: $(cli_crt_key_file_rsa) test-ca-sha256.crt cli-rsa.csr
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa -CA test-ca-sha256.crt -CAkey $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 4 -days 3653 -sha256 -in cli-rsa.csr -out $@
all_final += cli-rsa-sha256.crt

server2-rsa.csr: server2.key
	$(OPENSSL) req -new -key server2.key -passin "pass:$(test_ca_pwd_rsa)" -subj "/C=NL/O=PolarSSL/CN=localhost" -out $@
all_intermediate += server2-rsa.csr
server2-sha256.crt: server2-rsa.csr $(cli_crt_extensions_file)
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa -CA test-ca-sha256.crt -CAkey $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 4 -days 3653 -sha256 -in server2-rsa.csr -out $@
all_final += server2-sha256.crt

server2-ocsp.csr: server2.key
	$(OPENSSL) req -new -sha256 -key $< -passin "pass:$(test_ca_pwd_rsa)" -subj "/C=NL/O=PolarSSL/CN=localhost" -out $@
all_intermediate += server2-ocsp.csr
server2-ocsp.crt: server2-ocsp.csr $(cli_crt_extensions_file)
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions ocsp -CA test-ca-sha256.crt -CAkey $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 4 -days 3653 -sha256 -in $< -out $@
all_final += server2-ocsp.crt

server2-ocsp-nocheck.csr: server2.key
	$(OPENSSL) req -new -sha256 -key $< -passin "pass:$(test_ca_pwd_rsa)" -subj "/C=NL/O=PolarSSL/CN=localhost" -out $@
all_intermediate += server2-ocsp-nocheck.csr
server2-ocsp-nocheck.crt: server2-ocsp-nocheck.csr $(cli_crt_extensions_file)
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions ocsp-nocheck -CA test-ca-sha256.crt -CAkey $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 4 -days 3653 -sha256 -in $< -out $@
all_final += server2-ocsp-nocheck.crt

test-ca-index.txt:
	printf "" > $@
all_intermediate += test-ca-index.txt test-ca-index.txt.old
test-ca-index.txt.attr:
	printf "unique_subject = no" > $@
all_intermediate += test-ca-index.txt.attr test-ca-index.txt.attr.old
test-ca-serial.txt:
	printf "1000" > $@
all_intermediate += test-ca-serial.txt test-ca-serial.txt.old
server2-in-database.csr: server2.key $(test_ca_config_file) test-ca-index.txt test-ca-serial.txt test-ca-index.txt.attr
	$(OPENSSL) req -config $(test_ca_config_file) -key $< -passin "pass:$(test_ca_pwd_rsa)" -subj "/C=NL/O=PolarSSL/CN=Mbed TLS OCSP test cert" -out $@ -new -sha256
all_intermediate += server2-in-database.csr
server2-in-database.crt: server2-in-database.csr $(test_ca_config_file) test-ca-sha256.crt
	$(OPENSSL) ca -batch -config $(test_ca_config_file) -extensions server_cert -cert test-ca-sha256.crt -keyfile $(test_ca_key_file_rsa) -days 3653 -notext -md sha256 -passin "pass:$(test_ca_pwd_rsa)" -in $< -out $@
all_final += server2-in-database.crt
server2-in-database-revoked.csr: server2.key $(test_ca_config_file) test-ca-index.txt test-ca-serial.txt test-ca-index.txt.attr
	$(OPENSSL) req -config $(test_ca_config_file) -key $< -passin "pass:$(test_ca_pwd_rsa)" -subj "/C=NL/O=PolarSSL/CN=Mbed TLS OCSP revoked test cert" -out $@ -new -sha256
all_intermediate += server2-in-database-revoked.csr
server2-in-database-revoked.crt: server2-in-database-revoked.csr $(test_ca_config_file) test-ca-index.txt test-ca-serial.txt test-ca-index.txt.attr test-ca-sha256.crt
	$(OPENSSL) ca -batch -config $(test_ca_config_file) -extensions server_cert -cert test-ca-sha256.crt -keyfile $(test_ca_key_file_rsa) -days 3653 -notext -md sha256 -passin "pass:$(test_ca_pwd_rsa)" -in $< -out $@
	$(OPENSSL) ca -config $(test_ca_config_file) -passin "pass:$(test_ca_pwd_rsa)" -cert test-ca-sha256.crt -notext -keyfile $(test_ca_key_file_rsa) -revoke $@
all_final += server2-in-database-revoked.crt
server2_server2-in-database_server2-in-database-revoked.crt: server2.crt server2-in-database.crt server2-in-database-revoked.crt
	cat $^ > $@
all_final += server2_server2-in-database_server2-in-database-revoked.crt

################################################################
#### Generate OCSP responses using existing certificates
################################################################

ocsp-resp-status-malformed.der:
	@printf "\x30\x03\x0A\x01\x01" > $@
all_final += ocsp-resp-status-malformed.der

ocsp-resp-status-internalerror.der:
	@printf "\x30\x03\x0A\x01\x02" > $@
all_final += ocsp-resp-status-internal-error.der

ocsp-resp-status-try-later.der:
	@printf "\x30\x03\x0A\x01\x03" > $@
all_final += ocsp-resp-status-try-later.der

ocsp-resp-status-sig-required.der:
	@printf "\x30\x03\x0A\x01\x05" > $@
all_final += ocsp-resp-status-sig-required.der

ocsp-resp-status-unauthorized.der:
	@printf "\x30\x03\x0A\x01\x06" > $@
all_final += ocsp-resp-status-unauthorized.der

# The ocsp-resp-invalid-signature.der, ocsp-resp-future-this-update.der and
# ocsp-resp-future-produced-at.der targets print the binary data corrensponding
# to a generated ocsp-resp-no-certs-in-resp.der with a manually modified byte
# in the signature bitstring, producedAt and thisUpdate respectively to cause
# failures in the signature verification and time checks
ocsp-resp-invalid-signature.der:
	@printf "\x30\x82\x01\xB1\x0A\x01\x00\xA0\x82\x01\xAA\x30\x82\x01\xA6\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x01\x04\x82\x01\x97\x30\x82\x01\x93\x30\x7D\xA2\x16\x04\x14\xB4\x5A\xE4\xA5\xB3\xDE\xD2\x52\xF6\xB9\xD5\xA6\x95\x0F\xEB\x3E\xBC\xC7\xFD\xFF\x18\x0F\x32\x30\x31\x38\x30\x33\x30\x31\x32\x32\x30\x36\x30\x39\x5A\x30\x52\x30\x50\x30\x3B\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x04\x14\x0A\x15\x68\xA6\xD1\x87\x1F\x63\xAD\x9E\xDD\xB6\xB1\xCF\x6D\x46\xF2\x02\x09\x07\x04\x14\xB4\x5A\xE4\xA5\xB3\xDE\xD2\x52\xF6\xB9\xD5\xA6\x95\x0F\xEB\x3E\xBC\xC7\xFD\xFF\x02\x02\x10\x00\x80\x00\x18\x0F\x32\x30\x31\x38\x30\x33\x30\x31\x32\x32\x30\x36\x30\x39\x5A\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00\x03\xB3\x6E\xB8\xFC\x74\x98\x28\x06\x1D\x4A\x25\x8F\x0E\x92\xD3\xB2\x02\xC8\xFE\x30\xD2\x59\xAA\x6C\xB0\x52\xC5\x71\x50\xC1\x37\x33\x5D\xBD\xDC\x0F\x0F\xF1\x81\x74\x8C\x7B\xA7\x4E\xFE\xC7\xB1\x70\xF2\xE8\x42\xC7\x4D\x05\x35\x66\xAC\xD3\xF8\x18\x78\x2B\x65\xB7\x46\x3F\x71\x9D\xC4\xD3\xC6\x71\xA0\x1B\x5E\xE5\x6E\x78\xAE\xB1\xA6\x5B\x02\x45\x3A\x73\x44\xAA\xCF\xA1\x60\xB7\xD0\x8C\x84\xA0\xA4\x96\x89\x96\x5F\xD8\x1D\xFA\x0E\xBD\xE5\x5F\xD6\x87\x59\x4F\x0B\xE4\x85\x0F\x3F\xDC\x47\xEA\xF0\xC2\x11\xD3\xE4\x00\x2D\x9A\x86\xCC\x47\x47\x86\xC8\xFF\x52\x7D\x0B\xB9\xC1\x74\xD2\xA6\x96\x5F\x16\x7E\x42\xFB\xF6\x8D\xA5\xD7\x6E\x3C\xC3\xD3\x0E\x11\x47\xB9\x70\x71\xB8\x49\x98\xF5\x2F\xE7\x1B\x52\x4E\xB2\x3E\xB9\x46\xAD\x89\x9E\x7C\x7F\xF7\x51\xD9\x5C\x66\x12\x45\x5A\xE9\xD7\x80\x66\xA3\x19\xAE\x3D\x7D\xF2\x01\x60\x03\x4C\x85\x60\x51\x5C\x31\x91\xA4\xAB\x95\x21\xB5\xEB\xA8\x9D\xCF\x29\xD8\x78\x43\xF7\xA5\xD9\x8B\xC0\x88\xF6\xCE\xC5\x12\xC7\x21\x51\x44\x34\x43\xD1\x1E\x2F\xCD\x88\x8D\x47\x86\xED\x7C\x71\x55\x71\x0C\x09\xBC\x47" > $@
all_final += ocsp-resp-invalid-signature.der
ocsp-resp-future-produced-at.der:
	@printf "\x30\x82\x01\xB1\x0A\x01\x00\xA0\x82\x01\xAA\x30\x82\x01\xA6\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x01\x04\x82\x01\x97\x30\x82\x01\x93\x30\x7D\xA2\x16\x04\x14\xB4\x5A\xE4\xA5\xB3\xDE\xD2\x52\xF6\xB9\xD5\xA6\x95\x0F\xEB\x3E\xBC\xC7\xFD\xFF\x18\x0F\x32\x30\x32\x38\x30\x33\x30\x31\x32\x32\x30\x36\x30\x39\x5A\x30\x52\x30\x50\x30\x3B\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x04\x14\x0A\x15\x68\xA6\xD1\x87\x1F\x63\xAD\x9E\xDD\xB6\xB1\xCF\x6D\x46\xF2\x02\x09\x07\x04\x14\xB4\x5A\xE4\xA5\xB3\xDE\xD2\x52\xF6\xB9\xD5\xA6\x95\x0F\xEB\x3E\xBC\xC7\xFD\xFF\x02\x02\x10\x00\x80\x00\x18\x0F\x32\x30\x31\x38\x30\x33\x30\x31\x32\x32\x30\x36\x30\x39\x5A\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00\x03\xB3\x6E\xB8\xFC\x74\x98\x28\x06\x1D\x4A\x25\x8F\x0E\x92\xD3\xB2\x02\xC8\xFE\x30\xD2\x59\xAA\x6C\xB0\x52\xC5\x71\x50\xC1\x37\x33\x5D\xBD\xDC\x0F\x0F\xF1\x81\x74\x8C\x7B\xA7\x4E\xFE\xC7\xB1\x70\xF2\xE8\x42\xC7\x4D\x05\x35\x66\xAC\xD3\xF8\x18\x78\x2B\x65\xB7\x46\x3F\x71\x9D\xC4\xD3\xC6\x71\xA0\x1B\x5E\xE5\x6E\x78\xAE\xB1\xA6\x5B\x02\x45\x3A\x73\x44\xAA\xCF\xA1\x60\xB7\xD0\x8C\x84\xA0\xA4\x96\x89\x96\x5F\xD8\x1D\xFA\x0E\xBD\xE5\x5F\xD6\x87\x59\x4F\x0B\xE4\x85\x0F\x3F\xDC\x47\xEA\xF0\xC2\x11\xD3\xE4\x00\x2D\x9A\x86\xCC\x47\x47\x86\xC8\xFF\x52\x7D\x0B\xB9\xC1\x74\xD2\xA6\x96\x5F\x16\x7E\x42\xFB\xF6\x8D\xA5\xD7\x6E\x3C\xC3\xD3\x0E\x11\x47\xB9\x70\x71\xB8\x49\x98\xF5\x2F\xE7\x1B\x52\x4E\xB2\x3E\xB9\x46\xAD\x89\x9E\x7C\x7F\xF7\x51\xD9\x5C\x66\x12\x45\x5A\xE9\xD7\x80\x66\xA3\x19\xAE\x3D\x7D\xF2\x01\x60\x03\x4C\x85\x60\x51\x5C\x31\x91\xA4\xAB\x95\x21\xB5\xEB\xA8\x9D\xCF\x29\xD8\x78\x43\xF7\xA5\xD9\x8B\xC0\x88\xF6\xCE\xC5\x12\xC7\x21\x51\x44\x34\x43\xD1\x1E\x2F\xCD\x88\x8D\x47\x86\xED\x7C\x71\x55\x71\x0C\x09\xBC\x46" > $@
all_final += ocsp-resp-future-produced-at.der
ocsp-resp-future-this-update.der:
	@printf "\x30\x82\x01\xB1\x0A\x01\x00\xA0\x82\x01\xAA\x30\x82\x01\xA6\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x01\x04\x82\x01\x97\x30\x82\x01\x93\x30\x7D\xA2\x16\x04\x14\xB4\x5A\xE4\xA5\xB3\xDE\xD2\x52\xF6\xB9\xD5\xA6\x95\x0F\xEB\x3E\xBC\xC7\xFD\xFF\x18\x0F\x32\x30\x31\x38\x30\x33\x30\x31\x32\x32\x30\x36\x30\x39\x5A\x30\x52\x30\x50\x30\x3B\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x04\x14\x0A\x15\x68\xA6\xD1\x87\x1F\x63\xAD\x9E\xDD\xB6\xB1\xCF\x6D\x46\xF2\x02\x09\x07\x04\x14\xB4\x5A\xE4\xA5\xB3\xDE\xD2\x52\xF6\xB9\xD5\xA6\x95\x0F\xEB\x3E\xBC\xC7\xFD\xFF\x02\x02\x10\x00\x80\x00\x18\x0F\x32\x30\x32\x38\x30\x33\x30\x31\x32\x32\x30\x36\x30\x39\x5A\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00\x03\xB3\x6E\xB8\xFC\x74\x98\x28\x06\x1D\x4A\x25\x8F\x0E\x92\xD3\xB2\x02\xC8\xFE\x30\xD2\x59\xAA\x6C\xB0\x52\xC5\x71\x50\xC1\x37\x33\x5D\xBD\xDC\x0F\x0F\xF1\x81\x74\x8C\x7B\xA7\x4E\xFE\xC7\xB1\x70\xF2\xE8\x42\xC7\x4D\x05\x35\x66\xAC\xD3\xF8\x18\x78\x2B\x65\xB7\x46\x3F\x71\x9D\xC4\xD3\xC6\x71\xA0\x1B\x5E\xE5\x6E\x78\xAE\xB1\xA6\x5B\x02\x45\x3A\x73\x44\xAA\xCF\xA1\x60\xB7\xD0\x8C\x84\xA0\xA4\x96\x89\x96\x5F\xD8\x1D\xFA\x0E\xBD\xE5\x5F\xD6\x87\x59\x4F\x0B\xE4\x85\x0F\x3F\xDC\x47\xEA\xF0\xC2\x11\xD3\xE4\x00\x2D\x9A\x86\xCC\x47\x47\x86\xC8\xFF\x52\x7D\x0B\xB9\xC1\x74\xD2\xA6\x96\x5F\x16\x7E\x42\xFB\xF6\x8D\xA5\xD7\x6E\x3C\xC3\xD3\x0E\x11\x47\xB9\x70\x71\xB8\x49\x98\xF5\x2F\xE7\x1B\x52\x4E\xB2\x3E\xB9\x46\xAD\x89\x9E\x7C\x7F\xF7\x51\xD9\x5C\x66\x12\x45\x5A\xE9\xD7\x80\x66\xA3\x19\xAE\x3D\x7D\xF2\x01\x60\x03\x4C\x85\x60\x51\x5C\x31\x91\xA4\xAB\x95\x21\xB5\xEB\xA8\x9D\xCF\x29\xD8\x78\x43\xF7\xA5\xD9\x8B\xC0\x88\xF6\xCE\xC5\x12\xC7\x21\x51\x44\x34\x43\xD1\x1E\x2F\xCD\x88\x8D\x47\x86\xED\x7C\x71\x55\x71\x0C\x09\xBC\x46" > $@
all_final += ocsp-resp-future-this-update.der

ocsp-req-for-server2-in-database.der: server2-in-database.crt test-ca-sha256.crt
	$(OPENSSL) ocsp -issuer test-ca-sha256.crt -cert $< -no_nonce -reqout $@
all_intermediate += ocsp-req-for-server2-in-database.der
ocsp-req-for-server2.der: server2.crt test-ca-sha256.crt
	$(OPENSSL) ocsp -issuer test-ca-sha256.crt -cert $< -no_nonce -reqout $@
all_intermediate += ocsp-req-for-server2.der
ocsp-req-for-server2-in-database-revoked.der: server2-in-database-revoked.crt test-ca-sha256.crt
	$(OPENSSL) ocsp -issuer test-ca-sha256.crt -cert $< -no_nonce -reqout $@
all_intermediate += ocsp-req-for-server2-in-database-revoked.der
ocsp-req-for-good-revoked-unknown.der: server2.crt server2-in-database.crt server2-in-database-revoked.crt test-ca-sha256.crt
	$(OPENSSL) ocsp -issuer test-ca-sha256.crt -cert server2.crt -cert server2-in-database.crt -cert server2-in-database-revoked.crt -no_nonce -reqout $@
all_intermediate += ocsp-req-for-good-revoked-unknown.der

ocsp-resp-future-produced-at-this-update.der: ocsp-req-for-server2-in-database.der test-ca-index.txt test-ca-sha256.crt
	$(FAKETIME) -f "+9y" $(OPENSSL) ocsp -rsigner test-ca-sha256.crt -index test-ca-index.txt -rkey $(test_ca_key_file_rsa) -CA test-ca-sha256.crt -noverify -reqin $< -respout $@
all_final += ocsp-resp-future-produced-at-this-update.der
ocsp-resp-issuer-is-signer.der: ocsp-req-for-server2-in-database.der test-ca-index.txt test-ca-sha256.crt
	$(OPENSSL) ocsp -rsigner test-ca-sha256.crt -index test-ca-index.txt -rkey $(test_ca_key_file_rsa) -CA test-ca-sha256.crt -noverify -reqin $< -respout $@
all_final += ocsp-resp-issuer-is-signer.der
ocsp-resp-no-certs-in-resp.der: ocsp-req-for-server2-in-database.der test-ca-index.txt test-ca-sha256.crt
	$(OPENSSL) ocsp -rsigner test-ca-sha256.crt -index test-ca-index.txt -rkey $(test_ca_key_file_rsa) -CA test-ca-sha256.crt -resp_key_id -resp_no_certs -noverify -reqin $< -respout $@
ocsp-resp-expired-next-update.der: ocsp-req-for-server2-in-database.der test-ca-index.txt test-ca-sha256.crt
	$(OPENSSL) ocsp -rsigner test-ca-sha256.crt -index test-ca-index.txt -rkey $(test_ca_key_file_rsa) -CA test-ca-sha256.crt -noverify -nmin 0 -reqin $< -respout $@
all_final += ocsp-resp-expired-next-update.der
ocsp-resp-revoked-cert.der: ocsp-req-for-server2-in-database-revoked.der test-ca-index.txt test-ca-sha256.crt
	$(OPENSSL) ocsp -rsigner test-ca-sha256.crt -index test-ca-index.txt -rkey $(test_ca_key_file_rsa) -CA test-ca-sha256.crt -noverify -reqin $< -respout $@
all_final += ocsp-resp-revoked-cert.der
ocsp-resp-unknown-cert.der: ocsp-req-for-server2.der test-ca-index.txt test-ca-sha256.crt
	$(OPENSSL) ocsp -rsigner test-ca-sha256.crt -index test-ca-index.txt -rkey $(test_ca_key_file_rsa) -CA test-ca-sha256.crt -noverify -reqin $< -respout $@
all_final += ocsp-resp-unknown-cert.der
ocsp-resp-good-revoked-unknown.der: ocsp-req-for-good-revoked-unknown.der test-ca-index.txt test-ca-sha256.crt
	$(OPENSSL) ocsp -rsigner test-ca-sha256.crt -index test-ca-index.txt -rkey $(test_ca_key_file_rsa) -CA test-ca-sha256.crt -noverify -reqin $< -respout $@
all_final += ocsp-resp-good-revoked-unknown.der

################################################################
#### Meta targets
################################################################

all_final: $(all_final)
all: $(all_intermediate) $(all_final)

.PHONY: default all_final all

# These files should not be committed to the repository.
list_intermediate:
	@printf '%s\n' $(all_intermediate) | sort
# These files should be committed to the repository so that the test data is
# available upon checkout without running a randomized process depending on
# third-party tools.
list_final:
	@printf '%s\n' $(all_final) | sort
.PHONY: list_intermediate list_final

## Remove intermediate files
clean:
	rm -f $(all_intermediate)
## Remove all build products, even the ones that are committed
neat: clean
	rm -f $(all_final)
.PHONY: clean neat
