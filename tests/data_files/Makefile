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
server2-in-database.crt: server2-in-database.csr $(test_ca_config_file)
	$(OPENSSL) ca -batch -config $(test_ca_config_file) -extensions server_cert -cert test-ca-sha256.crt -keyfile $(test_ca_key_file_rsa) -days 3653 -notext -md sha256 -passin "pass:$(test_ca_pwd_rsa)" -in $< -out $@
all_final += server2-in-database.crt

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

ocsp-req-for-server2-in-database.der: server2-in-database.crt test-ca-sha256.crt
	$(OPENSSL) ocsp -issuer test-ca-sha256.crt -cert server2-in-database.crt -no_nonce -reqout $@
all_intermediate += ocsp-req-future-produced-at.der
ocsp-resp-future-produced-at.der: ocsp-req-for-server2-in-database.der test-ca-index.txt test-ca-sha256.crt
	$(FAKETIME) -f "+9y" $(OPENSSL) ocsp -rsigner test-ca-sha256.crt -index test-ca-index.txt -rkey $(test_ca_key_file_rsa) -CA test-ca-sha256.crt -noverify -reqin $< -respout $@
all_final += ocsp-resp-future-produced-at.der

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
