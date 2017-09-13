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
MBEDTLS_CERT_WRITE ?= $(PWD)/../../programs/x509/cert_write

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

test_ca_crt = test-ca.crt
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
server2-sha256.crt: server2-rsa.csr
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa -CA test-ca-sha256.crt -CAkey $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 4 -days 3653 -sha256 -in server2-rsa.csr -out $@
all_final += server2-sha256.crt

### Generate certificates for CRT write check tests
### The test files use the Mbed TLS generated certificates server1*.crt,
### but for comparison with OpenSSL also rules for OpenSSL-generated
### certificates server1*.crt.openssl are offered.
###
### Known differences:
### * OpenSSL encodes trailing zero-bits in bit-strings occurring in X.509 extension
###   as unused bits, while Mbed TLS doesn't.

test_ca_server1_db = test-ca.server1.db
test_ca_server1_serial = test-ca.server1.serial
test_ca_server1_config_file = test-ca.server1.opensslconf

server1.csr: server1.key server1_csr.opensslconf
	$(OPENSSL) req -keyform PEM -key server1.key -config server1_csr.opensslconf -out $@ -new
all_final += server1.csr

server1.crt: server1.key server1.csr $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.csr issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20110212144406 not_after=20210212144406 md=SHA1 version=3 output_file=$@
server1.noauthid.crt: server1.key server1.csr $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.csr issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20110212144406 not_after=20210212144406 md=SHA1 authority_identifier=0 version=3 output_file=$@
server1.der: server1.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server1.crt server1.noauthid.crt server1.der

server1.key_usage.crt: server1.key server1.csr $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.csr issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20110212144406 not_after=20210212144406 md=SHA1 key_usage=digital_signature,non_repudiation,key_encipherment version=3 output_file=$@
server1.key_usage_noauthid.crt: server1.key server1.csr $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.csr issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20110212144406 not_after=20210212144406 md=SHA1 key_usage=digital_signature,non_repudiation,key_encipherment authority_identifier=0 version=3 output_file=$@
server1.key_usage.der: server1.key_usage.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server1.key_usage.crt server1.key_usage_noauthid.crt server1.key_usage.der

server1.cert_type.crt: server1.key server1.csr $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.csr issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20110212144406 not_after=20210212144406 md=SHA1 ns_cert_type=ssl_server version=3 output_file=$@
server1.cert_type_noauthid.crt: server1.key server1.csr $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.csr issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20110212144406 not_after=20210212144406 md=SHA1 ns_cert_type=ssl_server authority_identifier=0 version=3 output_file=$@
server1.cert_type.der: server1.cert_type.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server1.cert_type.crt server1.cert_type_noauthid.crt server1.cert_type.der

server1.v1.crt: server1.key server1.csr $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.csr issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20110212144406 not_after=20210212144406 md=SHA1 version=1 output_file=$@
server1.v1.der: server1.v1.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server1.v1.crt server1.v1.der

# OpenSSL-generated certificates for comparison
# Also provide certificates in DER format to allow
# direct binary comparison using e.g. dumpasn1
server1.crt.openssl server1.key_usage.crt.openssl server1.cert_type.crt.openssl: server1.key server1.csr $(test_ca_crt) $(test_ca_key_file_rsa) $(test_ca_server1_config_file)
	echo "01" > $(test_ca_server1_serial)
	rm -f $(test_ca_server1_db)
	touch $(test_ca_server1_db)
	$(OPENSSL) ca -batch -passin "pass:$(test_ca_pwd_rsa)" -config $(test_ca_server1_config_file) -in server1.csr -extensions v3_ext -extfile $@.v3_ext -out $@
server1.der.openssl: server1.crt.openssl
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
server1.key_usage.der.openssl: server1.key_usage.crt.openssl
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
server1.cert_type.der.openssl: server1.cert_type.crt.openssl
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@

server1.v1.crt.openssl: server1.key server1.csr $(test_ca_crt) $(test_ca_key_file_rsa) $(test_ca_server1_config_file)
	echo "01" > $(test_ca_server1_serial)
	rm -f $(test_ca_server1_db)
	touch $(test_ca_server1_db)
	$(OPENSSL) ca -batch -passin "pass:$(test_ca_pwd_rsa)" -config $(test_ca_server1_config_file) -in server1.csr -out $@
server1.v1.der.openssl: server1.v1.crt.openssl
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@

server1_all: server1.csr server1.crt server1.noauthid.crt server1.crt.openssl server1.v1.crt server1.v1.crt.openssl server1.key_usage.crt server1.key_usage_noauthid.crt server1.key_usage.crt.openssl server1.cert_type.crt server1.cert_type_noauthid.crt server1.cert_type.crt.openssl server1.der server1.der.openssl server1.v1.der server1.v1.der.openssl server1.key_usage.der server1.key_usage.der.openssl server1.cert_type.der server1.cert_type.der.openssl

################################################################
#### Meta targets
################################################################

all_final: $(all_final)
all: $(all_intermediate) $(all_final)

.PHONY: default all_final all server1_all

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
