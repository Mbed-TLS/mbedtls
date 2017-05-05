OPENSSL = openssl

cli_crt_key_file_rsa = cli-rsa.key
cli_crt_extensions_file = cli.opensslconf
test_ca_key_file_rsa = test-ca.key
test_ca_pwd_rsa = PolarSSLTest
test_ca_config_file = test-ca.opensslconf

default: all_final

all_intermediate := # temporary files
all_final := # files used by tests

test-ca.csr: $(test_ca_key_file_rsa) $(test_ca_config_file)
	$(OPENSSL) req -new -config $(test_ca_config_file) -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -subj "/C=NL/O=PolarSSL/CN=PolarSSL Test CA" -out $@
all_intermediate += test-ca.csr
test-ca-sha1.crt: $(test_ca_key_file_rsa) $(test_ca_config_file) test-ca.csr
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 0 -days 3653 -sha1 -in test-ca.csr -out $@
all_final += test-ca-sha1.crt
test-ca-sha256.crt: $(test_ca_key_file_rsa) $(test_ca_config_file) test-ca.csr
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 0 -days 3653 -sha256 -in test-ca.csr -out $@
all_final += test-ca-sha256.crt

cli-rsa.csr: $(cli_crt_key_file_rsa)
	$(OPENSSL) req -new -key $(cli_crt_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -subj "/C=NL/O=PolarSSL/CN=PolarSSL Client 2" -out $@
all_intermediate += cli-rsa.csr
cli-rsa-sha1.crt: $(cli_crt_key_file_rsa) test-ca-sha1.crt cli-rsa.csr
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa -CA test-ca-sha1.crt -CAkey $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 4 -days 3653 -sha1 -in cli-rsa.csr -out $@
all_final += cli-rsa-sha1.crt
cli-rsa-sha256.crt: $(cli_crt_key_file_rsa) test-ca-sha256.crt cli-rsa.csr
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa -CA test-ca-sha256.crt -CAkey $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 4 -days 3653 -sha256 -in cli-rsa.csr -out $@
all_final += cli-rsa-sha256.crt

all_final: $(all_final)
all: $(all_intermediate) $(all_final)

# These files should not be committed to the repository.
list_intermediate:
	@printf '%s\n' $(all_intermediate) | sort
# These files should be committed to the repository so that the test data is
# available upon checkout without running a randomized process depending on
# third-party tools.
list_final:
	@printf '%s\n' $(all_final) | sort

clean:
	rm -f $(all_intermediate)
neat: clean
	rm -f $(all_final)
