## This file contains a record of how some of the test data was
## generated. The final build products are committed to the repository
## as well to make sure that the test data is identical. You do not
## need to use this makefile unless you're extending Mbed TLS's tests.

## Many data files were generated prior to the existence of this
## makefile, so the method of their generation was not recorded.

## Note that in addition to depending on the version of the data
## generation tool, many of the build outputs are randomized, so
## running this makefile twice would not produce the same results.

## Tools
OPENSSL ?= openssl
FAKETIME ?= faketime

TOP_DIR = ../..
MBEDTLS_CERT_WRITE ?= $(TOP_DIR)/programs/x509/cert_write
MBEDTLS_CERT_REQ ?= $(TOP_DIR)/programs/x509/cert_req


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

$(test_ca_key_file_rsa):
	$(OPENSSL) genrsa -aes-128-cbc -passout pass:$(test_ca_pwd_rsa) -out $@ 2048
all_final += $(test_ca_key_file_rsa)

test-ca.req.sha256: $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$(test_ca_key_file_rsa) password=$(test_ca_pwd_rsa) subject_name="C=NL,O=PolarSSL,CN=PolarSSL Test CA" md=SHA256
all_intermediate += test-ca.req.sha256

test-ca.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(MBEDTLS_CERT_WRITE) is_ca=1 serial=3 request_file=test-ca.req.sha256 selfsign=1 issuer_name="C=NL,O=PolarSSL,CN=PolarSSL Test CA" issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144400 not_after=20290210144400 md=SHA1 version=3 output_file=$@
all_final += test-ca.crt

test-ca.crt.der: test-ca.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += test-ca.crt.der

test-ca.key.der: $(test_ca_key_file_rsa)
	$(OPENSSL) pkey -in $< -out $@ -inform PEM -outform DER -passin "pass:$(test_ca_pwd_rsa)"
all_final += test-ca.key.der

# This is only used for generating cert_example_multi_nocn.crt
test-ca_nocn.crt: $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) is_ca=1 serial=3 selfsign=1 \
		subject_key=$(test_ca_key_file_rsa) subject_pwd=$(test_ca_pwd_rsa)  subject_name="C=NL" \
		issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) issuer_name="C=NL" \
		not_before=20190210144400 not_after=20290210144400 md=SHA1 version=3 output_file=$@
all_intermediate += test-ca_nocn.crt

test-ca-sha1.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(MBEDTLS_CERT_WRITE) is_ca=1 serial=3 request_file=test-ca.req.sha256 selfsign=1 issuer_name="C=NL,O=PolarSSL,CN=PolarSSL Test CA" issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144400 not_after=20290210144400 md=SHA1 version=3 output_file=$@
all_final += test-ca-sha1.crt

test-ca-sha1.crt.der: test-ca-sha1.crt
	$(OPENSSL) x509 -in $< -out $@ -inform PEM -outform DER
all_final += test-ca-sha1.crt.der

test-ca-sha256.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(MBEDTLS_CERT_WRITE) is_ca=1 serial=3 request_file=test-ca.req.sha256 selfsign=1 issuer_name="C=NL,O=PolarSSL,CN=PolarSSL Test CA" issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144400 not_after=20290210144400 md=SHA256 version=3 output_file=$@
all_final += test-ca-sha256.crt

test-ca-sha256.crt.der: test-ca-sha256.crt
	$(OPENSSL) x509 -in $< -out $@ -inform PEM -outform DER
all_final += test-ca-sha256.crt.der

test-ca_utf8.crt: $(test_ca_key_file_rsa)
	$(OPENSSL) req -x509 -new -nodes -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 3 -config $(test_ca_config_file) -sha1 -days 3653 -utf8 -subj "/C=NL/O=PolarSSL/CN=PolarSSL Test CA" -out $@
all_final += test-ca_utf8.crt

test-ca_printable.crt: $(test_ca_key_file_rsa)
	$(OPENSSL) req -x509 -new -nodes -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 3 -config $(test_ca_config_file) -sha1 -days 3653 -subj "/C=NL/O=PolarSSL/CN=PolarSSL Test CA" -out $@
all_final += test-ca_printable.crt

test-ca_uppercase.crt: $(test_ca_key_file_rsa)
	$(OPENSSL) req -x509 -new -nodes -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 3 -config $(test_ca_config_file) -sha1 -days 3653 -subj "/C=NL/O=PolarSSL/CN=PolarSSL Test CA" -out $@
all_final += test-ca_uppercase.crt

test_ca_key_file_rsa_alt = test-ca-alt.key

cert_example_multi.csr: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) req -new -subj "/C=NL/O=PolarSSL/CN=www.example.com" -set_serial 17 -config $(test_ca_config_file) -extensions dns_alt_names -days 3650 -key rsa_pkcs1_1024_clear.pem -out $@

cert_example_multi.crt: cert_example_multi.csr
	$(OPENSSL) x509 -req -CA $(test_ca_crt) -CAkey $(test_ca_key_file_rsa) -extfile $(test_ca_config_file) -extensions dns_alt_names -passin "pass:$(test_ca_pwd_rsa)" -set_serial 17 -days 3653 -sha256 -in $< > $@

cert_example_multi_nocn.csr: rsa_pkcs1_1024_clear.pem
	$(MBEDTLS_CERT_REQ) filename=$< output_file=$@ subject_name='C=NL'
all_intermediate += cert_example_multi_nocn.csr

cert_example_multi_nocn.crt: cert_example_multi_nocn.csr test-ca_nocn.crt
	$(OPENSSL) x509 -req -CA test-ca_nocn.crt -CAkey $(test_ca_key_file_rsa) \
		-extfile $(test_ca_config_file) -extensions ext_multi_nocn -passin "pass:$(test_ca_pwd_rsa)" \
		-set_serial  0xf7c67ff8e9a963f9 -days 3653 -sha1 -in $< > $@
all_final += cert_example_multi_nocn.crt

$(test_ca_key_file_rsa_alt):test-ca.opensslconf
	$(OPENSSL) genrsa -out $@ 2048
test-ca-alt.csr: $(test_ca_key_file_rsa_alt) $(test_ca_config_file)
	$(OPENSSL) req -new -config $(test_ca_config_file) -key $(test_ca_key_file_rsa_alt) -subj "/C=NL/O=PolarSSL/CN=PolarSSL Test CA" -out $@
all_intermediate += test-ca-alt.csr
test-ca-alt.crt: $(test_ca_key_file_rsa_alt) $(test_ca_config_file) test-ca-alt.csr
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -key $(test_ca_key_file_rsa_alt) -set_serial 0 -days 3653 -sha256 -in test-ca-alt.csr -out $@
all_final += test-ca-alt.crt
test-ca-alt-good.crt: test-ca-alt.crt test-ca-sha256.crt
	cat test-ca-alt.crt test-ca-sha256.crt > $@
all_final += test-ca-alt-good.crt
test-ca-good-alt.crt: test-ca-alt.crt test-ca-sha256.crt
	cat test-ca-sha256.crt test-ca-alt.crt > $@
all_final += test-ca-good-alt.crt

test_ca_crt_file_ec = test-ca2.crt
test_ca_key_file_ec = test-ca2.key

test-ca2.req.sha256: $(test_ca_key_file_ec)
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$(test_ca_key_file_ec) \
	subject_name="C=NL,O=PolarSSL,CN=Polarssl Test EC CA" md=SHA256
all_intermediate += test-ca2.req.sha256

test-ca2.crt: $(test_ca_key_file_ec) test-ca2.req.sha256
	$(MBEDTLS_CERT_WRITE) is_ca=1 serial=13926223505202072808 selfsign=1 \
		request_file=test-ca2.req.sha256 \
		issuer_name="C=NL,O=PolarSSL,CN=Polarssl Test EC CA" \
		issuer_key=$(test_ca_key_file_ec) \
		not_before=20190210144400 not_after=20290210144400 \
		md=SHA256 version=3 output_file=$@
all_final += test-ca2.crt

test-ca2.ku-%.crt: test-ca2.ku-%.crt.openssl.v3_ext $(test_ca_key_file_ec) test-ca2.req.sha256
	$(OPENSSL) x509 -req -in test-ca2.req.sha256 -extfile $< \
		-signkey $(test_ca_key_file_ec) -days 3653 -out $@

all_final += test-ca2.ku-crl.crt test-ca2.ku-crt.crt test-ca2.ku-crt_crl.crt \
	     test-ca2.ku-ds.crt

test-ca2-future.crt: $(test_ca_key_file_ec) test-ca2.req.sha256
	$(MBEDTLS_CERT_WRITE) is_ca=1 serial=13926223505202072808 request_file=test-ca2.req.sha256 selfsign=1 \
		issuer_name="C=NL,O=PolarSSL,CN=Polarssl Test EC CA" issuer_key=$(test_ca_key_file_ec) \
		not_before=20290210144400 not_after=20390210144400 md=SHA256 version=3 output_file=$@
all_intermediate += test-ca2-future.crt

test_ca_ec_cat := # files that concatenate different crt
test-ca2_cat-future-invalid.crt: test-ca2-future.crt server6.crt
test_ca_ec_cat += test-ca2_cat-future-invalid.crt
test-ca2_cat-future-present.crt: test-ca2-future.crt test-ca2.crt
test_ca_ec_cat += test-ca2_cat-future-present.crt
test-ca2_cat-present-future.crt: test-ca2.crt test-ca2-future.crt
test_ca_ec_cat += test-ca2_cat-present-future.crt
test-ca2_cat-present-past.crt: test-ca2.crt test-ca2-expired.crt
test_ca_ec_cat += test-ca2_cat-present-past.crt
test-ca2_cat-past-invalid.crt: test-ca2-expired.crt server6.crt
test_ca_ec_cat += test-ca2_cat-past-invalid.crt
test-ca2_cat-past-present.crt: test-ca2-expired.crt test-ca2.crt
test_ca_ec_cat += test-ca2_cat-past-present.crt
$(test_ca_ec_cat):
	cat $^ > $@
all_final += $(test_ca_ec_cat)

test-ca-any_policy.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_any_policy_ca \
		-key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" \
		-set_serial 0 -days 3653 -sha256 -in test-ca.req.sha256 -out $@
all_final += test-ca-any_policy.crt

test-ca-any_policy_ec.crt: $(test_ca_key_file_ec) test-ca.req_ec.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_any_policy_ca \
		-key $(test_ca_key_file_ec) -set_serial 0 -days 3653 -sha256 \
		-in test-ca.req_ec.sha256 -out $@
all_final += test-ca-any_policy_ec.crt

test-ca-any_policy_with_qualifier.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_any_policy_qualifier_ca -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 0 -days 3653 -sha256 -in test-ca.req.sha256 -out $@
all_final += test-ca-any_policy_with_qualifier.crt

test-ca-any_policy_with_qualifier_ec.crt: $(test_ca_key_file_ec) test-ca.req_ec.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_any_policy_qualifier_ca -key $(test_ca_key_file_ec) -set_serial 0 -days 3653 -sha256 -in test-ca.req_ec.sha256 -out $@
all_final += test-ca-any_policy_with_qualifier_ec.crt

test-ca-multi_policy.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_multi_policy_ca -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 0 -days 3653 -sha256 -in test-ca.req.sha256 -out $@
all_final += test-ca-multi_policy.crt

test-ca-multi_policy_ec.crt: $(test_ca_key_file_ec) test-ca.req_ec.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_multi_policy_ca -key $(test_ca_key_file_ec) -set_serial 0 -days 3653 -sha256 -in test-ca.req_ec.sha256 -out $@
all_final += test-ca-multi_policy_ec.crt

test-ca-unsupported_policy.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_unsupported_policy_ca -key $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 0 -days 3653 -sha256 -in test-ca.req.sha256 -out $@
all_final += test-ca-unsupported_policy.crt

test-ca-unsupported_policy_ec.crt: $(test_ca_key_file_ec) test-ca.req_ec.sha256
	$(OPENSSL) req -x509 -config $(test_ca_config_file) -extensions v3_unsupported_policy_ca -key $(test_ca_key_file_ec) -set_serial 0 -days 3653 -sha256 -in test-ca.req_ec.sha256 -out $@
all_final += test-ca-unsupported_policy_ec.crt

test-ca.req_ec.sha256: $(test_ca_key_file_ec)
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$(test_ca_key_file_ec) subject_name="C=NL, O=PolarSSL, CN=Polarssl Test EC CA" md=SHA256
all_intermediate += test-ca.req_ec.sha256

test-ca2.crt.der: $(test_ca_crt_file_ec)
	$(OPENSSL) x509 -in $(test_ca_crt_file_ec) -out $@ -inform PEM -outform DER
all_final += test-ca2.crt.der

test-ca2.key.der: $(test_ca_key_file_ec)
	$(OPENSSL) pkey -in $(test_ca_key_file_ec) -out $@ -inform PEM -outform DER
all_final += test-ca2.key.der

test_ca_crt_cat12 = test-ca_cat12.crt
$(test_ca_crt_cat12): $(test_ca_crt) $(test_ca_crt_file_ec)
	cat $(test_ca_crt) $(test_ca_crt_file_ec) > $@
all_final += $(test_ca_crt_cat12)

test_ca_crt_cat21 = test-ca_cat21.crt
$(test_ca_crt_cat21): $(test_ca_crt) $(test_ca_crt_file_ec)
	cat $(test_ca_crt_file_ec) $(test_ca_crt) > $@
all_final += $(test_ca_crt_cat21)

test-int-ca.csr: test-int-ca.key $(test_ca_config_file)
	$(OPENSSL) req -new -config $(test_ca_config_file) -key test-int-ca.key -subj "/C=NL/O=PolarSSL/CN=PolarSSL Test Intermediate CA" -out $@

test-int-ca2.csr: test-int-ca2.key $(test_ca_config_file)
	$(OPENSSL) req -new -config $(test_ca_config_file) -key test-int-ca2.key \
		-subj "/C=NL/O=PolarSSL/CN=PolarSSL Test Intermediate EC CA" -out $@

test-int-ca3.csr: test-int-ca3.key $(test_ca_config_file)
	$(OPENSSL) req -new -config $(test_ca_config_file) -key test-int-ca3.key \
		-subj "/C=UK/O=mbed TLS/CN=mbed TLS Test intermediate CA 3" -out $@

all_intermediate += test-int-ca.csr test-int-ca2.csr test-int-ca3.csr

test-int-ca.crt: $(test_ca_crt_file_ec) $(test_ca_key_file_ec) $(test_ca_config_file) test-int-ca.csr
	$(OPENSSL) x509 -req -extfile $(test_ca_config_file) -extensions v3_ca \
		-CA $(test_ca_crt_file_ec) -CAkey $(test_ca_key_file_ec) \
		-set_serial 14 -days 3653 -sha256 -in test-int-ca.csr -out $@

test-int-ca2.crt: $(test_ca_key_file_rsa) $(test_ca_crt) $(test_ca_config_file) test-int-ca2.csr
	$(OPENSSL) x509 -req -extfile $(test_ca_config_file) -extensions v3_ca -CA $(test_ca_crt) \
		-CAkey $(test_ca_key_file_rsa) -set_serial 15 -days 3653 -sha256 -in test-int-ca2.csr \
		-passin "pass:$(test_ca_pwd_rsa)" -out $@

# Note: This requests openssl version >= 3.x.xx
test-int-ca3.crt: test-int-ca2.crt test-int-ca2.key $(test_ca_config_file) test-int-ca3.csr
	$(OPENSSL) x509 -req -extfile $(test_ca_config_file) -extensions no_subj_auth_id \
		-CA test-int-ca2.crt -CAkey test-int-ca2.key -set_serial 77 -days 3653 \
			-sha256 -in test-int-ca3.csr -out $@

test-int-ca-exp.crt: $(test_ca_crt_file_ec) $(test_ca_key_file_ec) $(test_ca_config_file) test-int-ca.csr
	$(FAKETIME) -f -3653d $(OPENSSL) x509 -req -extfile $(test_ca_config_file) -extensions v3_ca -CA $(test_ca_crt_file_ec) -CAkey $(test_ca_key_file_ec) -set_serial 14 -days 3653 -sha256 -in test-int-ca.csr -out $@

all_final += test-int-ca-exp.crt test-int-ca.crt test-int-ca2.crt test-int-ca3.crt

enco-cert-utf8str.pem: rsa_pkcs1_1024_clear.pem
	$(MBEDTLS_CERT_WRITE) subject_key=rsa_pkcs1_1024_clear.pem subject_name="CN=dw.yonan.net" issuer_crt=enco-ca-prstr.pem issuer_key=rsa_pkcs1_1024_clear.pem not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@

crl-idp.pem: $(test_ca_crt) $(test_ca_key_file_rsa) $(test_ca_config_file)
	$(OPENSSL) ca -gencrl -batch -cert $(test_ca_crt) -keyfile $(test_ca_key_file_rsa) -key $(test_ca_pwd_rsa) -config $(test_ca_config_file) -name test_ca -md sha256 -crldays 3653 -crlexts crl_ext_idp -out $@
all_final += crl-idp.pem
crl-idpnc.pem: $(test_ca_crt) $(test_ca_key_file_rsa) $(test_ca_config_file)
	$(OPENSSL) ca -gencrl -batch -cert $(test_ca_crt) -keyfile $(test_ca_key_file_rsa) -key $(test_ca_pwd_rsa) -config $(test_ca_config_file) -name test_ca -md sha256 -crldays 3653 -crlexts crl_ext_idp_nc -out $@
all_final += crl-idpnc.pem

cli_crt_key_file_rsa = cli-rsa.key
cli_crt_extensions_file = cli.opensslconf

cli-rsa.csr: $(cli_crt_key_file_rsa)
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Client 2" md=SHA1
all_intermediate += cli-rsa.csr

cli-rsa-sha1.crt: cli-rsa.csr
	$(MBEDTLS_CERT_WRITE) request_file=$< serial=4 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@

cli-rsa-sha256.crt: cli-rsa.csr
	$(MBEDTLS_CERT_WRITE) request_file=$< serial=4 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA256 version=3 output_file=$@
all_final += cli-rsa-sha256.crt

cli-rsa-sha256.crt.der: cli-rsa-sha256.crt
	$(OPENSSL) x509 -in $< -out $@ -inform PEM -outform DER
all_final += cli-rsa-sha256.crt.der

cli-rsa-sha256-badalg.crt.der: cli-rsa-sha256.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/06092A864886F70D01010B0500/06092A864886F70D01010B0900/2" | xxd -r -p > $@
all_final += cli-rsa-sha256-badalg.crt.der

cli-rsa.key.der: $(cli_crt_key_file_rsa)
	$(OPENSSL) pkey -in $< -out $@ -inform PEM -outform DER
all_final += cli-rsa.key.der

test_ca_int_rsa1 = test-int-ca.crt
test_ca_int_ec = test-int-ca2.crt
test_ca_int_key_file_ec = test-int-ca2.key

# server7*

server7.csr: server7.key
	$(OPENSSL) req -new -key server7.key -subj "/C=NL/O=PolarSSL/CN=localhost" -out $@
all_intermediate += server7.csr

server7.crt: server7.csr $(test_ca_int_rsa1)
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa \
		-CA $(test_ca_int_rsa1) -CAkey test-int-ca.key \
		-set_serial 16 -days 3653 -sha256 -in server7.csr > $@
all_final += server7.crt

server7-expired.crt: server7.csr $(test_ca_int_rsa1)
	$(FAKETIME) -f -3653d $(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa -CA $(test_ca_int_rsa1) -CAkey test-int-ca.key -set_serial 16 -days 3653 -sha256 -in server7.csr | cat - $(test_ca_int_rsa1) > $@
all_final += server7-expired.crt

server7-future.crt: server7.csr $(test_ca_int_rsa1)
	$(FAKETIME) -f +3653d $(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa -CA $(test_ca_int_rsa1) -CAkey test-int-ca.key -set_serial 16 -days 3653 -sha256 -in server7.csr | cat - $(test_ca_int_rsa1) > $@
all_final += server7-future.crt

server7-badsign.crt: server7.crt $(test_ca_int_rsa1)
	{ head -n-2 $<; tail -n-2 $< | sed -e '1s/0\(=*\)$$/_\1/' -e '1s/[^_=]\(=*\)$$/0\1/' -e '1s/_/1/'; cat $(test_ca_int_rsa1); } > $@
all_final += server7-badsign.crt

server7_int-ca.crt: server7.crt $(test_ca_int_rsa1)
	cat server7.crt $(test_ca_int_rsa1) > $@
all_final += server7_int-ca.crt

server7_pem_space.crt: server7.crt $(test_ca_int_rsa1)
	cat server7.crt $(test_ca_int_rsa1) | sed '4s/\(.\)$$/ \1/' > $@
all_final += server7_pem_space.crt

server7_all_space.crt: server7.crt $(test_ca_int_rsa1)
	{ cat server7.crt | sed '4s/\(.\)$$/ \1/'; cat test-int-ca.crt | sed '4s/\(.\)$$/ \1/'; } > $@
all_final += server7_all_space.crt

server7_trailing_space.crt: server7.crt $(test_ca_int_rsa1)
	cat server7.crt $(test_ca_int_rsa1) | sed 's/\(.\)$$/\1 /' > $@
all_final += server7_trailing_space.crt

server7_int-ca_ca2.crt: server7.crt $(test_ca_int_rsa1) $(test_ca_crt_file_ec)
	cat server7.crt $(test_ca_int_rsa1) $(test_ca_crt_file_ec) > $@
all_final += server7_int-ca_ca2.crt

server7_int-ca-exp.crt: server7.crt test-int-ca-exp.crt
	cat server7.crt test-int-ca-exp.crt > $@
all_final += server7_int-ca-exp.crt

server7_spurious_int-ca.crt: server7.crt $(test_ca_int_ec) $(test_ca_int_rsa1)
	cat server7.crt $(test_ca_int_ec) $(test_ca_int_rsa1) > $@
all_final += server7_spurious_int-ca.crt

# server8*

server8.crt: server8.key
	$(MBEDTLS_CERT_WRITE) subject_key=$< subject_name="C=NL, O=PolarSSL, CN=localhost" serial=17 \
		issuer_crt=$(test_ca_int_ec) issuer_key=$(test_ca_int_key_file_ec) \
		not_before=20190210144406 not_after=20290210144406 \
		md=SHA256 version=3 output_file=$@
all_final += server8.crt

server8_int-ca2.crt: server8.crt $(test_ca_int_ec)
	cat $^ > $@
all_final += server8_int-ca2.crt

cli2.req.sha256: cli2.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Test Client 2" md=SHA256

all_final += server1.req.sha1
cli2.crt: cli2.req.sha256
	$(MBEDTLS_CERT_WRITE) request_file=cli2.req.sha256 serial=13 selfsign=0 issuer_name="C=NL,O=PolarSSL,CN=PolarSSL Test EC CA" issuer_key=$(test_ca_key_file_ec) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144400 not_after=20290210144400 md=SHA256 version=3 output_file=$@
all_final += cli2.crt

cli2.crt.der: cli2.crt
	$(OPENSSL) x509 -in $< -out $@ -inform PEM -outform DER
all_final += cli2.crt.der

cli2.key.der: cli2.key
	$(OPENSSL) pkey -in $< -out $@ -inform PEM -outform DER
all_final += cli2.key.der

server5_pwd_ec = PolarSSLTest

server5.crt.der: server5.crt
	$(OPENSSL) x509 -in $< -out $@ -inform PEM -outform DER
all_final += server5.crt.der

server5.key.der: server5.key
	$(OPENSSL) pkey -in $< -out $@ -inform PEM -outform DER
all_final += server5.key.der

server5.key.enc: server5.key
	$(OPENSSL) ec -aes256 -in $< -out $@ -passout "pass:$(server5_pwd_ec)"
all_final += server5.key.enc

server5-ss-expired.crt: server5.key
	$(FAKETIME) -f -3653d $(OPENSSL) req -x509 -new -subj "/C=UK/O=mbed TLS/OU=testsuite/CN=localhost" -days 3653 -sha256 -key $< -out $@
all_final += server5-ss-expired.crt

# try to forge a copy of test-int-ca3 with different key
server5-ss-forgeca.crt: server5.key
	$(OPENSSL) req -x509 -new -subj "/C=UK/O=mbed TLS/CN=mbed TLS Test intermediate CA 3" \
		-set_serial 77 -config $(test_ca_config_file) -extensions noext_ca \
		-days 3650 -sha256 -key $< -out $@
all_final += server5-ss-forgeca.crt

server5-selfsigned.crt: server5.key
	openssl req -x509 -key server5.key \
        -sha256 -days 3650 -nodes \
        -addext basicConstraints=critical,CA:FALSE \
        -addext keyUsage=critical,digitalSignature \
        -addext subjectKeyIdentifier=hash   \
        -addext authorityKeyIdentifier=none \
        -set_serial 0x53a2cb4b124ead837da894b2 \
        -subj "/CN=selfsigned/OU=testing/O=PolarSSL/C=NL" \
        -out $@
all_final += server5-selfsigned.crt

server5-othername.crt: server5.key
	$(OPENSSL) req -x509 -new -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS othername SAN" -set_serial 77 -config $(test_ca_config_file) -extensions othername_san -days 3650 -sha256 -key $< -out $@

server5-nonprintable_othername.crt: server5.key
	$(OPENSSL) req -x509 -new -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS non-printable othername SAN" -set_serial 77 -config $(test_ca_config_file) -extensions nonprintable_othername_san -days 3650 -sha256 -key $< -out $@

server5-unsupported_othername.crt: server5.key
	$(OPENSSL) req -x509 -new -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS unsupported othername SAN" -set_serial 77 -config $(test_ca_config_file) -extensions unsupported_othername_san -days 3650 -sha256 -key $< -out $@

server5-fan.crt: server5.key
	$(OPENSSL) req -x509 -new -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS FAN" -set_serial 77 -config $(test_ca_config_file) -extensions fan_cert -days 3650 -sha256 -key server5.key -out $@

server5-tricky-ip-san.crt: server5.key
	$(OPENSSL) req -x509 -new -subj "/C=UK/O=Mbed TLS/CN=Mbed TLS Tricky IP SAN" -set_serial 77 -config $(test_ca_config_file) -extensions tricky_ip_san -days 3650 -sha256 -key server5.key -out $@
all_final += server5-tricky-ip-san.crt

server5-der0.crt: server5.crt.der
	cp $< $@
server5-der1a.crt: server5.crt.der
	cp $< $@
	echo '00' | xxd -r -p | dd of=$@ bs=1 seek=$$(wc -c <$<) conv=notrunc
server5-der1b.crt: server5.crt.der
	cp $< $@
	echo 'c1' | xxd -r -p | dd of=$@ bs=1 seek=$$(wc -c <$<) conv=notrunc
server5-der2.crt: server5.crt.der
	cp $< $@
	echo 'b90a' | xxd -r -p | dd of=$@ bs=1 seek=$$(wc -c <$<) conv=notrunc
server5-der4.crt: server5.crt.der
	cp $< $@
	echo 'a710945f' | xxd -r -p | dd of=$@ bs=1 seek=$$(wc -c <$<) conv=notrunc
server5-der8.crt: server5.crt.der
	cp $< $@
	echo 'a4a7ff27267aaa0f' | xxd -r -p | dd of=$@ bs=1 seek=$$(wc -c <$<) conv=notrunc
server5-der9.crt: server5.crt.der
	cp $< $@
	echo 'cff8303376ffa47a29' | xxd -r -p | dd of=$@ bs=1 seek=$$(wc -c <$<) conv=notrunc
all_final += server5-der0.crt server5-der1b.crt server5-der4.crt \
			 server5-der9.crt server5-der1a.crt server5-der2.crt \
			 server5-der8.crt

test-int-ca3-badsign.crt: test-int-ca3.crt
	{ head -n-2 $<; tail -n-2 $< | sed -e '1s/0\(=*\)$$/_\1/' -e '1s/[^_=]\(=*\)$$/0\1/' -e '1s/_/1/'; } > $@
all_final += test-int-ca3-badsign.crt

# server9*

server9.csr: server9.key
	$(OPENSSL) req -new -subj "/C=NL/O=PolarSSL/CN=localhost" \
					-key $< -out $@
server9.crt: server9-sha1.crt
	cp $< $@
all_final += server9.crt
all_intermediate += server9.csr server9-sha1.crt

server9-%.crt: server9.csr $(test_ca_crt) $(test_ca_key_file_rsa)
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa \
		-passin "pass:$(test_ca_pwd_rsa)" -CA $(test_ca_crt) -CAkey $(test_ca_key_file_rsa) \
		-set_serial $(SERVER9_CRT_SERIAL) -days 3653 \
		-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:max \
		-sigopt rsa_mgf1_md:$(@:server9-%.crt=%) -$(@:server9-%.crt=%) \
		-in $< -out $@
server9-sha1.crt: SERVER9_CRT_SERIAL=22
server9-sha224.crt: SERVER9_CRT_SERIAL=23
server9-sha256.crt: SERVER9_CRT_SERIAL=24
server9-sha384.crt: SERVER9_CRT_SERIAL=25
server9-sha512.crt: SERVER9_CRT_SERIAL=26
all_final += server9-sha224.crt server9-sha256.crt server9-sha384.crt server9-sha512.crt

server9-defaults.crt: server9.csr $(test_ca_crt) $(test_ca_key_file_rsa)
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa \
		-passin "pass:$(test_ca_pwd_rsa)" -CA $(test_ca_crt) -CAkey $(test_ca_key_file_rsa) \
		-set_serial 72 -days 3653 \
		-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:max -sha1 \
		-in $< -out $@
all_final += server9-defaults.crt

server9-badsign.crt: server9.crt
	{ head -n-2 $<; tail -n-2 $< | sed -e '1s/0\(=*\)$$/_\1/' -e '1s/[^_=]\(=*\)$$/0\1/' -e '1s/_/1/'; } > $@
all_final += server9-badsign.crt

server9-with-ca.crt: server9.crt $(test_ca_crt)
	cat $^ > $@
all_final += server9-with-ca.crt

server9-bad-mgfhash.crt: server9.csr $(test_ca_crt) $(test_ca_key_file_rsa)
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa \
		-passin "pass:$(test_ca_pwd_rsa)" -CA $(test_ca_crt) -CAkey $(test_ca_key_file_rsa) \
		-set_serial 24 -days 3653 \
		-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:max \
		-sigopt rsa_mgf1_md:sha224 -sha256 \
		-in $< -out $@
all_final += server9-bad-mgfhash.crt

server9-bad-saltlen.crt: server9.csr $(test_ca_crt) $(test_ca_key_file_rsa) \
			 opensslcnf/server9.crt.v3_ext \
			 ../scripts/generate_server9_bad_saltlen.py
	../scripts/generate_server9_bad_saltlen.py --ca-name test-ca \
		--ca-password $(test_ca_pwd_rsa) --csr server9.csr \
		--openssl-extfile opensslcnf/server9.crt.v3_ext \
		--anounce_saltlen 0xde --actual_saltlen 0x20 \
		--output $@
all_final += server9-bad-saltlen.crt

# server10*

server10.crt: server10.key test-int-ca3.crt test-int-ca3.key
	$(MBEDTLS_CERT_WRITE) subject_key=$< subject_name="CN=localhost" serial=75 \
		issuer_crt=test-int-ca3.crt issuer_key=test-int-ca3.key \
		subject_identifier=0 authority_identifier=0 \
		not_before=20190210144406 not_after=20290210144406 \
		md=SHA256 version=3 output_file=$@
all_final += server10.crt
server10-badsign.crt: server10.crt
	{ head -n-2 $<; tail -n-2 $< | sed -e '1s/0\(=*\)$$/_\1/' -e '1s/[^_=]\(=*\)$$/0\1/' -e '1s/_/1/'; } > $@
all_final += server10-badsign.crt
server10-bs_int3.pem: server10-badsign.crt test-int-ca3.crt
	cat server10-badsign.crt test-int-ca3.crt > $@
all_final += server10-bs_int3.pem
server10_int3-bs.pem: server10.crt test-int-ca3-badsign.crt
	cat server10.crt test-int-ca3-badsign.crt > $@
all_final += server10_int3-bs.pem
server10_int3_int-ca2.crt: server10.crt test-int-ca3.crt $(test_ca_int_ec)
	cat $^ > $@
all_final += server10_int3_int-ca2.crt
server10_int3_int-ca2_ca.crt: server10.crt test-int-ca3.crt $(test_ca_int_ec) $(test_ca_crt)
	cat $^ > $@
all_final += server10_int3_int-ca2_ca.crt
server10_int3_spurious_int-ca2.crt: server10.crt test-int-ca3.crt $(test_ca_int_rsa1) $(test_ca_int_ec)
	cat $^ > $@
all_final += server10_int3_spurious_int-ca2.crt

rsa_pkcs1_2048_public.pem: server8.key
	$(OPENSSL)  rsa -in $< -outform PEM -RSAPublicKey_out -out $@
all_final += rsa_pkcs1_2048_public.pem

rsa_pkcs1_2048_public.der: rsa_pkcs1_2048_public.pem
	$(OPENSSL) rsa -RSAPublicKey_in -in $< -outform DER -RSAPublicKey_out -out $@
all_final += rsa_pkcs1_2048_public.der

rsa_pkcs8_2048_public.pem: server8.key
	$(OPENSSL)  rsa -in $< -outform PEM -pubout -out $@
all_final += rsa_pkcs8_2048_public.pem

rsa_pkcs8_2048_public.der: rsa_pkcs8_2048_public.pem
	$(OPENSSL) rsa -pubin -in $< -outform DER -pubout -out $@
all_final += rsa_pkcs8_2048_public.der

# Generate crl_cat_*.pem
# - crt_cat_*.pem: (1+2) concatenations in various orders:
#     ec = crl-ec-sha256.pem, ecfut = crl-future.pem
#     rsa = crl.pem, rsabadpem = same with pem error, rsaexp = crl_expired.pem

crl_cat_ec-rsa.pem:crl-ec-sha256.pem crl.pem
	cat $^ > $@

crl_cat_rsa-ec.pem:crl.pem crl-ec-sha256.pem
	cat $^ > $@

all_final += crl_cat_ec-rsa.pem crl_cat_rsa-ec.pem

################################################################
#### Generate various RSA keys
################################################################

### Password used for PKCS1-encoded encrypted RSA keys
keys_rsa_basic_pwd = testkey

### Password used for PKCS8-encoded encrypted RSA keys
keys_rsa_pkcs8_pwd = PolarSSLTest

### Basic 1024-, 2048- and 4096-bit unencrypted RSA keys from which
### all other encrypted RSA keys are derived.
rsa_pkcs1_1024_clear.pem:
	$(OPENSSL) genrsa -out $@ 1024
all_final += rsa_pkcs1_1024_clear.pem
rsa_pkcs1_2048_clear.pem:
	$(OPENSSL) genrsa -out $@ 2048
all_final += rsa_pkcs1_2048_clear.pem
rsa_pkcs1_4096_clear.pem:
	$(OPENSSL) genrsa -out $@ 4096
all_final += rsa_pkcs1_4096_clear.pem

###
### PKCS1-encoded, encrypted RSA keys
###

### 1024-bit
rsa_pkcs1_1024_des.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) rsa -des -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_1024_des.pem
rsa_pkcs1_1024_3des.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) rsa -des3 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_1024_3des.pem
rsa_pkcs1_1024_aes128.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) rsa -aes128 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_1024_aes128.pem
rsa_pkcs1_1024_aes192.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) rsa -aes192 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_1024_aes192.pem
rsa_pkcs1_1024_aes256.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) rsa -aes256 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_1024_aes256.pem
keys_rsa_enc_basic_1024: rsa_pkcs1_1024_des.pem rsa_pkcs1_1024_3des.pem rsa_pkcs1_1024_aes128.pem rsa_pkcs1_1024_aes192.pem rsa_pkcs1_1024_aes256.pem

# 2048-bit
rsa_pkcs1_2048_des.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) rsa -des -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_2048_des.pem
rsa_pkcs1_2048_3des.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) rsa -des3 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_2048_3des.pem
rsa_pkcs1_2048_aes128.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) rsa -aes128 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_2048_aes128.pem
rsa_pkcs1_2048_aes192.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) rsa -aes192 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_2048_aes192.pem
rsa_pkcs1_2048_aes256.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) rsa -aes256 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_2048_aes256.pem
keys_rsa_enc_basic_2048: rsa_pkcs1_2048_des.pem rsa_pkcs1_2048_3des.pem rsa_pkcs1_2048_aes128.pem rsa_pkcs1_2048_aes192.pem rsa_pkcs1_2048_aes256.pem

# 4096-bit
rsa_pkcs1_4096_des.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) rsa -des -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_4096_des.pem
rsa_pkcs1_4096_3des.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) rsa -des3 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_4096_3des.pem
rsa_pkcs1_4096_aes128.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) rsa -aes128 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_4096_aes128.pem
rsa_pkcs1_4096_aes192.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) rsa -aes192 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_4096_aes192.pem
rsa_pkcs1_4096_aes256.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) rsa -aes256 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
all_final += rsa_pkcs1_4096_aes256.pem
keys_rsa_enc_basic_4096: rsa_pkcs1_4096_des.pem rsa_pkcs1_4096_3des.pem rsa_pkcs1_4096_aes128.pem rsa_pkcs1_4096_aes192.pem rsa_pkcs1_4096_aes256.pem

###
### PKCS8-v1 encoded, encrypted RSA keys
###

### 1024-bit
rsa_pkcs8_pbe_sha1_1024_3des.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
all_final += rsa_pkcs8_pbe_sha1_1024_3des.der
rsa_pkcs8_pbe_sha1_1024_3des.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
all_final += rsa_pkcs8_pbe_sha1_1024_3des.pem
keys_rsa_enc_pkcs8_v1_1024_3des: rsa_pkcs8_pbe_sha1_1024_3des.pem rsa_pkcs8_pbe_sha1_1024_3des.der

rsa_pkcs8_pbe_sha1_1024_2des.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
all_final += rsa_pkcs8_pbe_sha1_1024_2des.der
rsa_pkcs8_pbe_sha1_1024_2des.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
all_final += rsa_pkcs8_pbe_sha1_1024_2des.pem
keys_rsa_enc_pkcs8_v1_1024_2des: rsa_pkcs8_pbe_sha1_1024_2des.pem rsa_pkcs8_pbe_sha1_1024_2des.der

rsa_pkcs8_pbe_sha1_1024_rc4_128.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-RC4-128
all_final += rsa_pkcs8_pbe_sha1_1024_rc4_128.der
rsa_pkcs8_pbe_sha1_1024_rc4_128.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-RC4-128
all_final += rsa_pkcs8_pbe_sha1_1024_rc4_128.pem
keys_rsa_enc_pkcs8_v1_1024_rc4_128: rsa_pkcs8_pbe_sha1_1024_rc4_128.pem rsa_pkcs8_pbe_sha1_1024_rc4_128.der

keys_rsa_enc_pkcs8_v1_1024: keys_rsa_enc_pkcs8_v1_1024_3des keys_rsa_enc_pkcs8_v1_1024_2des keys_rsa_enc_pkcs8_v1_1024_rc4_128

### 2048-bit
rsa_pkcs8_pbe_sha1_2048_3des.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
all_final += rsa_pkcs8_pbe_sha1_2048_3des.der
rsa_pkcs8_pbe_sha1_2048_3des.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
all_final += rsa_pkcs8_pbe_sha1_2048_3des.pem
keys_rsa_enc_pkcs8_v1_2048_3des: rsa_pkcs8_pbe_sha1_2048_3des.pem rsa_pkcs8_pbe_sha1_2048_3des.der

rsa_pkcs8_pbe_sha1_2048_2des.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
all_final += rsa_pkcs8_pbe_sha1_2048_2des.der
rsa_pkcs8_pbe_sha1_2048_2des.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
all_final += rsa_pkcs8_pbe_sha1_2048_2des.pem
keys_rsa_enc_pkcs8_v1_2048_2des: rsa_pkcs8_pbe_sha1_2048_2des.pem rsa_pkcs8_pbe_sha1_2048_2des.der

rsa_pkcs8_pbe_sha1_2048_rc4_128.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-RC4-128
all_final += rsa_pkcs8_pbe_sha1_2048_rc4_128.der
rsa_pkcs8_pbe_sha1_2048_rc4_128.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-RC4-128
all_final += rsa_pkcs8_pbe_sha1_2048_rc4_128.pem
keys_rsa_enc_pkcs8_v1_2048_rc4_128: rsa_pkcs8_pbe_sha1_2048_rc4_128.pem rsa_pkcs8_pbe_sha1_2048_rc4_128.der

keys_rsa_enc_pkcs8_v1_2048: keys_rsa_enc_pkcs8_v1_2048_3des keys_rsa_enc_pkcs8_v1_2048_2des keys_rsa_enc_pkcs8_v1_2048_rc4_128

### 4096-bit
rsa_pkcs8_pbe_sha1_4096_3des.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
all_final += rsa_pkcs8_pbe_sha1_4096_3des.der
rsa_pkcs8_pbe_sha1_4096_3des.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
all_final += rsa_pkcs8_pbe_sha1_4096_3des.pem
keys_rsa_enc_pkcs8_v1_4096_3des: rsa_pkcs8_pbe_sha1_4096_3des.pem rsa_pkcs8_pbe_sha1_4096_3des.der

rsa_pkcs8_pbe_sha1_4096_2des.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
all_final += rsa_pkcs8_pbe_sha1_4096_2des.der
rsa_pkcs8_pbe_sha1_4096_2des.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
all_final += rsa_pkcs8_pbe_sha1_4096_2des.pem
keys_rsa_enc_pkcs8_v1_4096_2des: rsa_pkcs8_pbe_sha1_4096_2des.pem rsa_pkcs8_pbe_sha1_4096_2des.der

rsa_pkcs8_pbe_sha1_4096_rc4_128.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-RC4-128
all_final += rsa_pkcs8_pbe_sha1_4096_rc4_128.der
rsa_pkcs8_pbe_sha1_4096_rc4_128.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-RC4-128
all_final += rsa_pkcs8_pbe_sha1_4096_rc4_128.pem
keys_rsa_enc_pkcs8_v1_4096_rc4_128: rsa_pkcs8_pbe_sha1_4096_rc4_128.pem rsa_pkcs8_pbe_sha1_4096_rc4_128.der

keys_rsa_enc_pkcs8_v1_4096: keys_rsa_enc_pkcs8_v1_4096_3des keys_rsa_enc_pkcs8_v1_4096_2des keys_rsa_enc_pkcs8_v1_4096_rc4_128

###
### PKCS8-v2 encoded, encrypted RSA keys, no PRF specified (default for OpenSSL1.0: hmacWithSHA1)
###

### 1024-bit
rsa_pkcs8_pbes2_pbkdf2_1024_3des.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des.der
rsa_pkcs8_pbes2_pbkdf2_1024_3des.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des.pem
keys_rsa_enc_pkcs8_v2_1024_3des: rsa_pkcs8_pbes2_pbkdf2_1024_3des.der rsa_pkcs8_pbes2_pbkdf2_1024_3des.pem

rsa_pkcs8_pbes2_pbkdf2_1024_des.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des.der
rsa_pkcs8_pbes2_pbkdf2_1024_des.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des.pem
keys_rsa_enc_pkcs8_v2_1024_des: rsa_pkcs8_pbes2_pbkdf2_1024_des.der rsa_pkcs8_pbes2_pbkdf2_1024_des.pem

keys_rsa_enc_pkcs8_v2_1024: keys_rsa_enc_pkcs8_v2_1024_3des keys_rsa_enc_pkcs8_v2_1024_des

### 2048-bit
rsa_pkcs8_pbes2_pbkdf2_2048_3des.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des.der
rsa_pkcs8_pbes2_pbkdf2_2048_3des.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des.pem
keys_rsa_enc_pkcs8_v2_2048_3des: rsa_pkcs8_pbes2_pbkdf2_2048_3des.der rsa_pkcs8_pbes2_pbkdf2_2048_3des.pem

rsa_pkcs8_pbes2_pbkdf2_2048_des.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des.der
rsa_pkcs8_pbes2_pbkdf2_2048_des.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des.pem
keys_rsa_enc_pkcs8_v2_2048_des: rsa_pkcs8_pbes2_pbkdf2_2048_des.der rsa_pkcs8_pbes2_pbkdf2_2048_des.pem

keys_rsa_enc_pkcs8_v2_2048: keys_rsa_enc_pkcs8_v2_2048_3des keys_rsa_enc_pkcs8_v2_2048_des

### 4096-bit
rsa_pkcs8_pbes2_pbkdf2_4096_3des.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des.der
rsa_pkcs8_pbes2_pbkdf2_4096_3des.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des.pem
keys_rsa_enc_pkcs8_v2_4096_3des: rsa_pkcs8_pbes2_pbkdf2_4096_3des.der rsa_pkcs8_pbes2_pbkdf2_4096_3des.pem

rsa_pkcs8_pbes2_pbkdf2_4096_des.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des.der
rsa_pkcs8_pbes2_pbkdf2_4096_des.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des.pem
keys_rsa_enc_pkcs8_v2_4096_des: rsa_pkcs8_pbes2_pbkdf2_4096_des.der rsa_pkcs8_pbes2_pbkdf2_4096_des.pem

keys_rsa_enc_pkcs8_v2_4096: keys_rsa_enc_pkcs8_v2_4096_3des keys_rsa_enc_pkcs8_v2_4096_des

###
### PKCS8-v2 encoded, encrypted RSA keys, PRF hmacWithSHA224
###

### 1024-bit
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha224.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA224 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha224.der
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha224.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA224 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha224.pem
keys_rsa_enc_pkcs8_v2_1024_3des_sha224: rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha224.der rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha224.pem

rsa_pkcs8_pbes2_pbkdf2_1024_des_sha224.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA224 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha224.der
rsa_pkcs8_pbes2_pbkdf2_1024_des_sha224.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA224 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha224.pem
keys_rsa_enc_pkcs8_v2_1024_des_sha224: rsa_pkcs8_pbes2_pbkdf2_1024_des_sha224.der rsa_pkcs8_pbes2_pbkdf2_1024_des_sha224.pem

keys_rsa_enc_pkcs8_v2_1024_sha224: keys_rsa_enc_pkcs8_v2_1024_3des_sha224 keys_rsa_enc_pkcs8_v2_1024_des_sha224

### 2048-bit
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA224 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.der
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA224 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.pem
keys_rsa_enc_pkcs8_v2_2048_3des_sha224: rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.der rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.pem

rsa_pkcs8_pbes2_pbkdf2_2048_des_sha224.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA224 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha224.der
rsa_pkcs8_pbes2_pbkdf2_2048_des_sha224.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA224 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha224.pem
keys_rsa_enc_pkcs8_v2_2048_des_sha224: rsa_pkcs8_pbes2_pbkdf2_2048_des_sha224.der rsa_pkcs8_pbes2_pbkdf2_2048_des_sha224.pem

keys_rsa_enc_pkcs8_v2_2048_sha224: keys_rsa_enc_pkcs8_v2_2048_3des_sha224 keys_rsa_enc_pkcs8_v2_2048_des_sha224

### 4096-bit
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha224.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA224 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha224.der
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha224.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA224 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha224.pem
keys_rsa_enc_pkcs8_v2_4096_3des_sha224: rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha224.der rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha224.pem

rsa_pkcs8_pbes2_pbkdf2_4096_des_sha224.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA224 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha224.der
rsa_pkcs8_pbes2_pbkdf2_4096_des_sha224.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA224 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha224.pem
keys_rsa_enc_pkcs8_v2_4096_des_sha224: rsa_pkcs8_pbes2_pbkdf2_4096_des_sha224.der rsa_pkcs8_pbes2_pbkdf2_4096_des_sha224.pem

keys_rsa_enc_pkcs8_v2_4096_sha224: keys_rsa_enc_pkcs8_v2_4096_3des_sha224 keys_rsa_enc_pkcs8_v2_4096_des_sha224

###
### PKCS8-v2 encoded, encrypted RSA keys, PRF hmacWithSHA256
###

### 1024-bit
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha256.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA256 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha256.der
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha256.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA256 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha256.pem
keys_rsa_enc_pkcs8_v2_1024_3des_sha256: rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha256.der rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha256.pem

rsa_pkcs8_pbes2_pbkdf2_1024_des_sha256.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA256 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha256.der
rsa_pkcs8_pbes2_pbkdf2_1024_des_sha256.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA256 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha256.pem
keys_rsa_enc_pkcs8_v2_1024_des_sha256: rsa_pkcs8_pbes2_pbkdf2_1024_des_sha256.der rsa_pkcs8_pbes2_pbkdf2_1024_des_sha256.pem

keys_rsa_enc_pkcs8_v2_1024_sha256: keys_rsa_enc_pkcs8_v2_1024_3des_sha256 keys_rsa_enc_pkcs8_v2_1024_des_sha256

### 2048-bit
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha256.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA256 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha256.der
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha256.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA256 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha256.pem
keys_rsa_enc_pkcs8_v2_2048_3des_sha256: rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha256.der rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha256.pem

rsa_pkcs8_pbes2_pbkdf2_2048_des_sha256.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA256 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha256.der
rsa_pkcs8_pbes2_pbkdf2_2048_des_sha256.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA256 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha256.pem
keys_rsa_enc_pkcs8_v2_2048_des_sha256: rsa_pkcs8_pbes2_pbkdf2_2048_des_sha256.der rsa_pkcs8_pbes2_pbkdf2_2048_des_sha256.pem

keys_rsa_enc_pkcs8_v2_2048_sha256: keys_rsa_enc_pkcs8_v2_2048_3des_sha256 keys_rsa_enc_pkcs8_v2_2048_des_sha256

### 4096-bit
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha256.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA256 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha256.der
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha256.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA256 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha256.pem
keys_rsa_enc_pkcs8_v2_4096_3des_sha256: rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha256.der rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha256.pem

rsa_pkcs8_pbes2_pbkdf2_4096_des_sha256.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA256 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha256.der
rsa_pkcs8_pbes2_pbkdf2_4096_des_sha256.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA256 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha256.pem
keys_rsa_enc_pkcs8_v2_4096_des_sha256: rsa_pkcs8_pbes2_pbkdf2_4096_des_sha256.der rsa_pkcs8_pbes2_pbkdf2_4096_des_sha256.pem

keys_rsa_enc_pkcs8_v2_4096_sha256: keys_rsa_enc_pkcs8_v2_4096_3des_sha256 keys_rsa_enc_pkcs8_v2_4096_des_sha256

###
### PKCS8-v2 encoded, encrypted RSA keys, PRF hmacWithSHA384
###

### 1024-bit
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha384.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA384 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha384.der
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha384.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA384 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha384.pem
keys_rsa_enc_pkcs8_v2_1024_3des_sha384: rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha384.der rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha384.pem

rsa_pkcs8_pbes2_pbkdf2_1024_des_sha384.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA384 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha384.der
rsa_pkcs8_pbes2_pbkdf2_1024_des_sha384.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA384 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha384.pem
keys_rsa_enc_pkcs8_v2_1024_des_sha384: rsa_pkcs8_pbes2_pbkdf2_1024_des_sha384.der rsa_pkcs8_pbes2_pbkdf2_1024_des_sha384.pem

keys_rsa_enc_pkcs8_v2_1024_sha384: keys_rsa_enc_pkcs8_v2_1024_3des_sha384 keys_rsa_enc_pkcs8_v2_1024_des_sha384

### 2048-bit
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA384 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.der
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA384 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.pem
keys_rsa_enc_pkcs8_v2_2048_3des_sha384: rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.der rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.pem

rsa_pkcs8_pbes2_pbkdf2_2048_des_sha384.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA384 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha384.der
rsa_pkcs8_pbes2_pbkdf2_2048_des_sha384.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA384 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha384.pem
keys_rsa_enc_pkcs8_v2_2048_des_sha384: rsa_pkcs8_pbes2_pbkdf2_2048_des_sha384.der rsa_pkcs8_pbes2_pbkdf2_2048_des_sha384.pem

keys_rsa_enc_pkcs8_v2_2048_sha384: keys_rsa_enc_pkcs8_v2_2048_3des_sha384 keys_rsa_enc_pkcs8_v2_2048_des_sha384

### 4096-bit
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha384.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA384 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha384.der
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha384.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA384 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha384.pem
keys_rsa_enc_pkcs8_v2_4096_3des_sha384: rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha384.der rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha384.pem

rsa_pkcs8_pbes2_pbkdf2_4096_des_sha384.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA384 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha384.der
rsa_pkcs8_pbes2_pbkdf2_4096_des_sha384.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA384 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha384.pem
keys_rsa_enc_pkcs8_v2_4096_des_sha384: rsa_pkcs8_pbes2_pbkdf2_4096_des_sha384.der rsa_pkcs8_pbes2_pbkdf2_4096_des_sha384.pem

keys_rsa_enc_pkcs8_v2_4096_sha384: keys_rsa_enc_pkcs8_v2_4096_3des_sha384 keys_rsa_enc_pkcs8_v2_4096_des_sha384

###
### PKCS8-v2 encoded, encrypted RSA keys, PRF hmacWithSHA512
###

### 1024-bit
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha512.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA512 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha512.der
rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha512.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA512 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha512.pem
keys_rsa_enc_pkcs8_v2_1024_3des_sha512: rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha512.der rsa_pkcs8_pbes2_pbkdf2_1024_3des_sha512.pem

rsa_pkcs8_pbes2_pbkdf2_1024_des_sha512.der: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA512 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha512.der
rsa_pkcs8_pbes2_pbkdf2_1024_des_sha512.pem: rsa_pkcs1_1024_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA512 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_1024_des_sha512.pem
keys_rsa_enc_pkcs8_v2_1024_des_sha512: rsa_pkcs8_pbes2_pbkdf2_1024_des_sha512.der rsa_pkcs8_pbes2_pbkdf2_1024_des_sha512.pem

keys_rsa_enc_pkcs8_v2_1024_sha512: keys_rsa_enc_pkcs8_v2_1024_3des_sha512 keys_rsa_enc_pkcs8_v2_1024_des_sha512

### 2048-bit
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA512 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.der
rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA512 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.pem
keys_rsa_enc_pkcs8_v2_2048_3des_sha512: rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.der rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.pem

rsa_pkcs8_pbes2_pbkdf2_2048_des_sha512.der: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA512 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha512.der
rsa_pkcs8_pbes2_pbkdf2_2048_des_sha512.pem: rsa_pkcs1_2048_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA512 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_2048_des_sha512.pem
keys_rsa_enc_pkcs8_v2_2048_des_sha512: rsa_pkcs8_pbes2_pbkdf2_2048_des_sha512.der rsa_pkcs8_pbes2_pbkdf2_2048_des_sha512.pem

keys_rsa_enc_pkcs8_v2_2048_sha512: keys_rsa_enc_pkcs8_v2_2048_3des_sha512 keys_rsa_enc_pkcs8_v2_2048_des_sha512

### 4096-bit
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha512.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA512 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha512.der
rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha512.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -v2prf hmacWithSHA512 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha512.pem
keys_rsa_enc_pkcs8_v2_4096_3des_sha512: rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha512.der rsa_pkcs8_pbes2_pbkdf2_4096_3des_sha512.pem

rsa_pkcs8_pbes2_pbkdf2_4096_des_sha512.der: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8 -topk8 -v2 des -v2prf hmacWithSHA512 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha512.der
rsa_pkcs8_pbes2_pbkdf2_4096_des_sha512.pem: rsa_pkcs1_4096_clear.pem
	$(OPENSSL) pkcs8  -topk8 -v2 des -v2prf hmacWithSHA512 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
all_final += rsa_pkcs8_pbes2_pbkdf2_4096_des_sha512.pem
keys_rsa_enc_pkcs8_v2_4096_des_sha512: rsa_pkcs8_pbes2_pbkdf2_4096_des_sha512.der rsa_pkcs8_pbes2_pbkdf2_4096_des_sha512.pem

keys_rsa_enc_pkcs8_v2_4096_sha512: keys_rsa_enc_pkcs8_v2_4096_3des_sha512 keys_rsa_enc_pkcs8_v2_4096_des_sha512

###
### Rules to generate all RSA keys from a particular class
###

### Generate basic unencrypted RSA keys
keys_rsa_unenc: rsa_pkcs1_1024_clear.pem rsa_pkcs1_2048_clear.pem rsa_pkcs1_4096_clear.pem

### Generate PKCS1-encoded encrypted RSA keys
keys_rsa_enc_basic: keys_rsa_enc_basic_1024 keys_rsa_enc_basic_2048 keys_rsa_enc_basic_4096

### Generate PKCS8-v1 encrypted RSA keys
keys_rsa_enc_pkcs8_v1: keys_rsa_enc_pkcs8_v1_1024 keys_rsa_enc_pkcs8_v1_2048 keys_rsa_enc_pkcs8_v1_4096

### Generate PKCS8-v2 encrypted RSA keys
keys_rsa_enc_pkcs8_v2: keys_rsa_enc_pkcs8_v2_1024 keys_rsa_enc_pkcs8_v2_2048 keys_rsa_enc_pkcs8_v2_4096 keys_rsa_enc_pkcs8_v2_1024_sha224 keys_rsa_enc_pkcs8_v2_2048_sha224 keys_rsa_enc_pkcs8_v2_4096_sha224 keys_rsa_enc_pkcs8_v2_1024_sha256 keys_rsa_enc_pkcs8_v2_2048_sha256 keys_rsa_enc_pkcs8_v2_4096_sha256 keys_rsa_enc_pkcs8_v2_1024_sha384 keys_rsa_enc_pkcs8_v2_2048_sha384 keys_rsa_enc_pkcs8_v2_4096_sha384 keys_rsa_enc_pkcs8_v2_1024_sha512 keys_rsa_enc_pkcs8_v2_2048_sha512 keys_rsa_enc_pkcs8_v2_4096_sha512

### Generate all RSA keys
keys_rsa_all: keys_rsa_unenc keys_rsa_enc_basic keys_rsa_enc_pkcs8_v1 keys_rsa_enc_pkcs8_v2

################################################################
#### Generate various EC keys
################################################################

###
### PKCS8 encoded
###

ec_prv.pk8.der:
	$(OPENSSL) genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime192v1 -pkeyopt ec_param_enc:named_curve -out $@ -outform DER
all_final += ec_prv.pk8.der

# ### Instructions for creating `ec_prv.pk8nopub.der`,
# ### `ec_prv.pk8nopubparam.der`, and `ec_prv.pk8param.der` by hand from
# ### `ec_prv.pk8.der`.
#
# These instructions assume you are familiar with ASN.1 DER encoding and can
# use a hex editor to manipulate DER.
#
# The relevant ASN.1 definitions for a PKCS#8 encoded Elliptic Curve key are:
#
# PrivateKeyInfo ::= SEQUENCE {
#   version                   Version,
#   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
#   privateKey                PrivateKey,
#   attributes           [0]  IMPLICIT Attributes OPTIONAL
# }
#
# AlgorithmIdentifier  ::=  SEQUENCE  {
#   algorithm   OBJECT IDENTIFIER,
#   parameters  ANY DEFINED BY algorithm OPTIONAL
# }
#
# ECParameters ::= CHOICE {
#   namedCurve         OBJECT IDENTIFIER
#   -- implicitCurve   NULL
#   -- specifiedCurve  SpecifiedECDomain
# }
#
# ECPrivateKey ::= SEQUENCE {
#   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
#   privateKey     OCTET STRING,
#   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
#   publicKey  [1] BIT STRING OPTIONAL
# }
#
# `ec_prv.pk8.der` as generatde above by OpenSSL should have the following
# fields:
#
# * privateKeyAlgorithm       namedCurve
# * privateKey.parameters     NOT PRESENT
# * privateKey.publicKey      PRESENT
# * attributes                NOT PRESENT
#
# # ec_prv.pk8nopub.der
#
# Take `ec_prv.pk8.der` and remove `privateKey.publicKey`.
#
# # ec_prv.pk8nopubparam.der
#
# Take `ec_prv.pk8nopub.der` and add `privateKey.parameters`, the same value as
# `privateKeyAlgorithm.namedCurve`. Don't forget to add the explicit tag.
#
# # ec_prv.pk8param.der
#
# Take `ec_prv.pk8.der` and add `privateKey.parameters`, the same value as
# `privateKeyAlgorithm.namedCurve`. Don't forget to add the explicit tag.

ec_prv.pk8.pem: ec_prv.pk8.der
	$(OPENSSL) pkey -in $< -inform DER -out $@
all_final += ec_prv.pk8.pem
ec_prv.pk8nopub.pem: ec_prv.pk8nopub.der
	$(OPENSSL) pkey -in $< -inform DER -out $@
all_final += ec_prv.pk8nopub.pem
ec_prv.pk8nopubparam.pem: ec_prv.pk8nopubparam.der
	$(OPENSSL) pkey -in $< -inform DER -out $@
all_final += ec_prv.pk8nopubparam.pem
ec_prv.pk8param.pem: ec_prv.pk8param.der
	$(OPENSSL) pkey -in $< -inform DER -out $@
all_final += ec_prv.pk8param.pem

ec_pub.pem: ec_prv.sec1.der
	$(OPENSSL) pkey -in $< -inform DER -outform PEM -pubout -out $@
all_final += ec_pub.pem

################################################################
#### Convert PEM keys to DER format
################################################################
server1.pubkey.der: server1.pubkey
	$(OPENSSL) pkey -pubin -in $< -out $@ -outform DER
all_final += server1.pubkey.der

rsa4096_pub.der: rsa4096_pub.pem
	$(OPENSSL) pkey -pubin -in $< -out $@ -outform DER
all_final += rsa4096_pub.der

ec_pub.der: ec_pub.pem
	$(OPENSSL) pkey -pubin -in $< -out $@ -outform DER
all_final += ec_pub.der

ec_521_pub.der: ec_521_pub.pem
	$(OPENSSL) pkey -pubin -in $< -out $@ -outform DER
all_final += ec_521_pub.der

ec_bp512_pub.der: ec_bp512_pub.pem
	$(OPENSSL) pkey -pubin -in $< -out $@ -outform DER
all_final += ec_bp512_pub.der

server1.key.der: server1.key
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += server1.key.der

rsa4096_prv.der: rsa4096_prv.pem
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += rsa4096_prv.der

ec_prv.sec1.der: ec_prv.sec1.pem
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += ec_prv.sec1.der

ec_256_long_prv.der: ec_256_long_prv.pem
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += ec_256_long_prv.der

ec_521_prv.der: ec_521_prv.pem
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += ec_521_prv.der

ec_521_short_prv.der: ec_521_short_prv.pem
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += ec_521_short_prv.der

ec_bp512_prv.der: ec_bp512_prv.pem
	$(OPENSSL) pkey -in $< -out $@ -outform DER
all_final += ec_bp512_prv.der

################################################################
### Generate CSRs for X.509 write test suite
################################################################

server1.req.sha1: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA1
all_final += server1.req.sha1

server1.req.md4: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=MD4
all_final += server1.req.md4

server1.req.md5: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=MD5
all_final += server1.req.md5

server1.req.sha224: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA224
all_final += server1.req.sha224

server1.req.sha256: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA256
all_final += server1.req.sha256

server1.req.sha256.ext: server1.key
	# Generating this with OpenSSL as a comparison point to test we're getting the same result
	openssl req -new -out $@ -key $< -subj '/C=NL/O=PolarSSL/CN=PolarSSL Server 1' -sha256 -addext "extendedKeyUsage=serverAuth"
all_final += server1.req.sha256.ext

server1.req.sha384: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA384
all_final += server1.req.sha384

server1.req.sha512: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA512
all_final += server1.req.sha512

server1.req.cert_type: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< ns_cert_type=ssl_server subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA1
all_final += server1.req.cert_type

server1.req.key_usage: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< key_usage=digital_signature,non_repudiation,key_encipherment subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA1
all_final += server1.req.key_usage

server1.req.ku-ct: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< key_usage=digital_signature,non_repudiation,key_encipherment ns_cert_type=ssl_server subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA1
all_final += server1.req.ku-ct

server1.req.key_usage_empty: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA1 force_key_usage=1
all_final += server1.req.key_usage_empty

server1.req.cert_type_empty: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Server 1" md=SHA1 force_ns_cert_type=1
all_final += server1.req.cert_type_empty

server1.req.commas.sha256: server1.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL\, Commas,CN=PolarSSL Server 1" md=SHA256
all_final += server1.req.commas.sha256

# server2*

server2_pwd_ec = PolarSSLTest

server2.req.sha256: server2.key
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=localhost" md=SHA256
all_intermediate += server2.req.sha256

server2.crt.der: server2.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server2.crt.der

server2-sha256.crt.der: server2-sha256.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server2-sha256.crt.der

server2.key.der: server2.key
	$(OPENSSL) pkey -in $< -out $@ -inform PEM -outform DER
all_final += server2.key.der

server2.key.enc: server2.key
	$(OPENSSL) rsa -aes256 -in $< -out $@ -passout "pass:$(server2_pwd_ec)"
all_final += server2.key.enc

# server5*

server5.csr: server5.key
	$(OPENSSL) req -new -subj "/C=NL/O=PolarSSL/CN=localhost" \
					-key $< -out $@
all_intermediate += server5.csr
server5.crt: server5-sha256.crt
	cp $< $@
all_intermediate += server5-sha256.crt
server5-sha%.crt: server5.csr $(test_ca_crt_file_ec) $(test_ca_key_file_ec) server5.crt.openssl.v3_ext
	$(OPENSSL) x509 -req -CA $(test_ca_crt_file_ec) -CAkey $(test_ca_key_file_ec) \
				-extfile server5.crt.openssl.v3_ext -set_serial 9 -days 3650 \
				-sha$(@:server5-sha%.crt=%) -in $< -out $@
all_final += server5.crt server5-sha1.crt server5-sha224.crt server5-sha384.crt server5-sha512.crt

server5-badsign.crt: server5.crt
	{ head -n-2 $<; tail -n-2 $< | sed -e '1s/0\(=*\)$$/_\1/' -e '1s/[^_=]\(=*\)$$/0\1/' -e '1s/_/1/'; } > $@
all_final += server5-badsign.crt

# The use of 'Server 1' in the DN is intentional here, as the DN is hardcoded in the x509_write test suite.'
server5.req.ku.sha1: server5.key
	$(OPENSSL) req -key $< -out $@ -new -nodes -subj "/C=NL/O=PolarSSL/CN=PolarSSL Server 1" -sha1 -addext keyUsage=digitalSignature,nonRepudiation
all_final += server5.req.ku.sha1

server5.ku-ds.crt: SERVER5_CRT_SERIAL=45
server5.ku-ds.crt: SERVER5_KEY_USAGE=digital_signature
server5.ku-ka.crt: SERVER5_CRT_SERIAL=46
server5.ku-ka.crt: SERVER5_KEY_USAGE=key_agreement
server5.ku-ke.crt: SERVER5_CRT_SERIAL=47
server5.ku-ke.crt: SERVER5_KEY_USAGE=key_encipherment
server5.eku-cs.crt: SERVER5_CRT_SERIAL=58
server5.eku-cs.crt: SERVER5_EXT_KEY_USAGE=codeSigning
server5.eku-cs_any.crt: SERVER5_CRT_SERIAL=59
server5.eku-cs_any.crt: SERVER5_EXT_KEY_USAGE=codeSigning,any
server5.eku-cli.crt: SERVER5_CRT_SERIAL=60
server5.eku-cli.crt: SERVER5_EXT_KEY_USAGE=clientAuth
server5.eku-srv_cli.crt: SERVER5_CRT_SERIAL=61
server5.eku-srv_cli.crt: SERVER5_EXT_KEY_USAGE=serverAuth,clientAuth
server5.eku-srv.crt: SERVER5_CRT_SERIAL=62
server5.eku-srv.crt: SERVER5_EXT_KEY_USAGE=serverAuth
server5.ku-%.crt: SERVER5_EXT_OPTS=key_usage=$(SERVER5_KEY_USAGE)
# The commands for server5.eku-*.crt is invalid because `ext_key_usage` was not supported by
# `cert_write` in 2.28. This would be fixed by #8083.
server5.eku-%.crt: SERVER5_EXT_OPTS=ext_key_usage=$(SERVER5_EXT_KEY_USAGE)
server5.%.crt: server5.key
	$(MBEDTLS_CERT_WRITE) \
		subject_key=$< subject_name="C=NL,O=PolarSSL,CN=localhost" serial=$(SERVER5_CRT_SERIAL) \
		issuer_crt=$(test_ca_crt_file_ec) issuer_key=$(test_ca_key_file_ec) $(SERVER5_EXT_OPTS) \
		not_before=20190210144406 not_after=20290210144406 md=SHA256 version=3 output_file=$@
all_final += server5.ku-ka.crt server5.ku-ke.crt server5.ku-ds.crt
all_final += server5.eku-cs.crt server5.eku-cs_any.crt server5.eku-cli.crt server5.eku-srv_cli.crt server5.eku-srv.crt

# server6*

server6.csr: server6.key
	$(OPENSSL) req -new -subj "/C=NL/O=PolarSSL/CN=localhost" \
					-key $< -out $@
all_intermediate += server6.csr
server6.crt: server6.csr $(test_ca_crt_file_ec) $(test_ca_key_file_ec)
	$(OPENSSL) x509 -req -CA $(test_ca_crt_file_ec) -CAkey $(test_ca_key_file_ec) \
				-extfile server5.crt.openssl.v3_ext -set_serial 10 -days 3650 -sha256 -in $< -out $@
all_final += server6.crt

server6-ss-child.csr : server6.key
	$(OPENSSL) req -new -subj "/CN=selfsigned-child/OU=testing/O=PolarSSL/C=NL" \
		-key $< -out $@
all_intermediate += server6-ss-child.csr
server6-ss-child.crt: server6-ss-child.csr server5-selfsigned.crt server5.key server6-ss-child.crt.openssl.v3_ext
	$(OPENSSL) x509 -req -CA server5-selfsigned.crt -CAkey server5.key \
		-extfile server6-ss-child.crt.openssl.v3_ext \
		-set_serial 0x53a2cb5822399474a7ec79ec \
		-days 3650 -sha256 -in $< -out $@
all_final += server6-ss-child.crt


################################################################
### Generate certificates for CRT write check tests
################################################################

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

# server1*

server1.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 \
		issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) \
		issuer_pwd=$(test_ca_pwd_rsa) version=1 \
		not_before=20190210144406 not_after=20290210144406 \
		md=SHA1 version=3 output_file=$@
server1.noauthid.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA1 authority_identifier=0 version=3 output_file=$@
server1.crt.der: server1.crt
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA1 authority_identifier=0 version=3 output_file=$@
server1.der: server1.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
server1.commas.crt: server1.key server1.req.commas.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.commas.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@
all_final += server1.crt server1.noauthid.crt server1.crt.der server1.commas.crt

server1.key_usage.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 key_usage=digital_signature,non_repudiation,key_encipherment version=3 output_file=$@
server1.key_usage_noauthid.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 key_usage=digital_signature,non_repudiation,key_encipherment authority_identifier=0 version=3 output_file=$@
server1.key_usage.der: server1.key_usage.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server1.key_usage.crt server1.key_usage_noauthid.crt server1.key_usage.der

server1.cert_type.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 ns_cert_type=ssl_server version=3 output_file=$@
server1.cert_type_noauthid.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 ns_cert_type=ssl_server authority_identifier=0 version=3 output_file=$@
server1.cert_type.der: server1.cert_type.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server1.cert_type.crt server1.cert_type_noauthid.crt server1.cert_type.der

server1.v1.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 version=1 output_file=$@
server1.v1.der: server1.v1.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server1.v1.crt server1.v1.der

server1.ca.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) version=1 not_before=20190210144406 not_after=20290210144406 md=SHA1 is_ca=1 version=3 output_file=$@
server1.ca_noauthid.crt: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa)
	$(MBEDTLS_CERT_WRITE) request_file=server1.req.sha256 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA1 authority_identifier=0 is_ca=1 version=3 output_file=$@
server1.ca.der: server1.ca.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server1.ca.crt server1.ca_noauthid.crt server1.ca.der

server1-nospace.crt: server1.key test-ca.crt
	$(MBEDTLS_CERT_WRITE) subject_key=$< serial=31\
		subject_name="C=NL,O=PolarSSL,CN=polarssl.example"  \
		issuer_crt=test-ca.crt issuer_key=$(test_ca_key_file_rsa) \
		issuer_pwd=$(test_ca_pwd_rsa) \
		not_before=20190210144406 not_after=20290210144406 \
		md=SHA256 version=3 authority_identifier=1 \
		output_file=$@
all_final += server1-nospace.crt

server1_ca.crt: server1.crt $(test_ca_crt)
	cat server1.crt $(test_ca_crt) > $@
all_final += server1_ca.crt

cert_sha1.crt: server1.key
	$(MBEDTLS_CERT_WRITE) subject_key=server1.key subject_name="C=NL, O=PolarSSL, CN=PolarSSL Cert SHA1" serial=7 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@
all_final += cert_sha1.crt

cert_sha224.crt: server1.key
	$(MBEDTLS_CERT_WRITE) subject_key=server1.key subject_name="C=NL, O=PolarSSL, CN=PolarSSL Cert SHA224" serial=8 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA224 version=3 output_file=$@
all_final += cert_sha224.crt

cert_sha256.crt: server1.key
	$(MBEDTLS_CERT_WRITE) subject_key=server1.key subject_name="C=NL, O=PolarSSL, CN=PolarSSL Cert SHA256" serial=9 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA256 version=3 output_file=$@
all_final += cert_sha256.crt

cert_sha384.crt: server1.key
	$(MBEDTLS_CERT_WRITE) subject_key=server1.key subject_name="C=NL, O=PolarSSL, CN=PolarSSL Cert SHA384" serial=10 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA384 version=3 output_file=$@
all_final += cert_sha384.crt

cert_sha512.crt: server1.key
	$(MBEDTLS_CERT_WRITE) subject_key=server1.key subject_name="C=NL, O=PolarSSL, CN=PolarSSL Cert SHA512" serial=11 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA512 version=3 output_file=$@
all_final += cert_sha512.crt

cert_example_wildcard.crt: server1.key
	$(MBEDTLS_CERT_WRITE) subject_key=server1.key subject_name="C=NL, O=PolarSSL, CN=*.example.com" serial=12 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@
all_final += cert_example_wildcard.crt

# OpenSSL-generated certificates for comparison
# Also provide certificates in DER format to allow
# direct binary comparison using e.g. dumpasn1
server1.crt.openssl server1.key_usage.crt.openssl server1.cert_type.crt.openssl: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa) $(test_ca_server1_config_file)
	echo "01" > $(test_ca_server1_serial)
	rm -f $(test_ca_server1_db)
	touch $(test_ca_server1_db)
	$(OPENSSL) ca -batch -passin "pass:$(test_ca_pwd_rsa)" -config $(test_ca_server1_config_file) -in server1.req.sha256 -extensions v3_ext -extfile $@.v3_ext -out $@
server1.der.openssl: server1.crt.openssl
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
server1.key_usage.der.openssl: server1.key_usage.crt.openssl
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
server1.cert_type.der.openssl: server1.cert_type.crt.openssl
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@

server1.v1.crt.openssl: server1.key server1.req.sha256 $(test_ca_crt) $(test_ca_key_file_rsa) $(test_ca_server1_config_file)
	echo "01" > $(test_ca_server1_serial)
	rm -f $(test_ca_server1_db)
	touch $(test_ca_server1_db)
	$(OPENSSL) ca -batch -passin "pass:$(test_ca_pwd_rsa)" -config $(test_ca_server1_config_file) -in server1.req.sha256 -out $@
server1.v1.der.openssl: server1.v1.crt.openssl
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@

# To revoke certificate in the openssl database:
#
# $(OPENSSL) ca -gencrl -batch -cert $(test_ca_crt) -keyfile $(test_ca_key_file_rsa) -key $(test_ca_pwd_rsa) -config $(test_ca_server1_config_file) -md sha256 -crldays 365 -revoke server1.crt

crl.pem: $(test_ca_crt) $(test_ca_key_file_rsa) $(test_ca_config_file)
	$(OPENSSL) ca -gencrl -batch -cert $(test_ca_crt) -keyfile $(test_ca_key_file_rsa) -key $(test_ca_pwd_rsa) -config $(test_ca_server1_config_file) -md sha1 -crldays 3653 -out $@

crl-futureRevocationDate.pem: $(test_ca_crt) $(test_ca_key_file_rsa) \
			      $(test_ca_config_file) \
			      test-ca.server1.future-crl.db \
			      test-ca.server1.future-crl.opensslconf
	$(FAKETIME) -f '+10y' $(OPENSSL) ca -gencrl \
		-config test-ca.server1.future-crl.opensslconf -crldays 365 \
		-passin "pass:$(test_ca_pwd_rsa)" -out $@

server1_all: crl.pem crl-futureRevocationDate.pem server1.crt server1.noauthid.crt server1.crt.openssl server1.v1.crt server1.v1.crt.openssl server1.key_usage.crt server1.key_usage_noauthid.crt server1.key_usage.crt.openssl server1.cert_type.crt server1.cert_type_noauthid.crt server1.cert_type.crt.openssl server1.der server1.der.openssl server1.v1.der server1.v1.der.openssl server1.key_usage.der server1.key_usage.der.openssl server1.cert_type.der server1.cert_type.der.openssl

# server2*

server2.crt: server2.req.sha256
	$(MBEDTLS_CERT_WRITE) request_file=server2.req.sha256 serial=2 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@
all_final += server2.crt

server2.der: server2.crt
	$(OPENSSL) x509 -inform PEM -in $< -outform DER -out $@
all_final += server2.crt server2.der

server2-sha256.crt: server2.req.sha256
	$(MBEDTLS_CERT_WRITE) request_file=server2.req.sha256 serial=2 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20190210144406 not_after=20290210144406 md=SHA256 version=3 output_file=$@
all_final += server2-sha256.crt

server2.ku-ka.crt: SERVER2_CRT_SERIAL=42
server2.ku-ka.crt: SERVER2_KEY_USAGE=key_agreement
server2.ku-ke.crt: SERVER2_CRT_SERIAL=43
server2.ku-ke.crt: SERVER2_KEY_USAGE=key_encipherment
server2.ku-ds.crt: SERVER2_CRT_SERIAL=44
server2.ku-ds.crt: SERVER2_KEY_USAGE=digital_signature
server2.ku-ds_ke.crt: SERVER2_CRT_SERIAL=48
server2.ku-ds_ke.crt: SERVER2_KEY_USAGE=digital_signature,key_encipherment
server2.ku-%.crt: server2.req.sha256
	$(MBEDTLS_CERT_WRITE) request_file=server2.req.sha256 serial=$(SERVER2_CRT_SERIAL) \
		issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) \
		key_usage="$(SERVER2_KEY_USAGE)" \
		not_before=20190210144406 not_after=20290210144406 md=SHA1 version=3 output_file=$@
all_final += server2.ku-ka.crt server2.ku-ke.crt server2.ku-ds.crt server2.ku-ds_ke.crt

server2-badsign.crt: server2.crt
	{ head -n-2 $<; tail -n-2 $< | sed -e '1s/0\(=*\)$$/_\1/' -e '1s/[^_=]\(=*\)$$/0\1/' -e '1s/_/1/'; } > $@
all_final += server2-badsign.crt

# server3*

server3.crt: server3.key
	$(MBEDTLS_CERT_WRITE) subject_key=$< subject_name="C=NL,O=PolarSSL,CN=localhost" serial=13 \
		issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) \
		not_before=20190210144406 not_after=20290210144406 \
		md=SHA1 version=3 output_file=$@
all_final += server3.crt

# server4*

server4.crt: server4.key
	$(MBEDTLS_CERT_WRITE) subject_key=$< subject_name="C=NL,O=PolarSSL,CN=localhost" serial=8 \
		issuer_crt=$(test_ca_crt_file_ec) issuer_key=$(test_ca_key_file_ec) \
		not_before=20190210144400 not_after=20290210144400 \
		md=SHA256 version=3 output_file=$@
all_final += server4.crt

# MD2, MD4, MD5 test certificates

cert_md_test_key = $(cli_crt_key_file_rsa)

cert_md2.csr: $(cert_md_test_key)
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Cert MD2" md=MD2
all_intermediate += cert_md2.csr

cert_md2.crt: cert_md2.csr
	$(MBEDTLS_CERT_WRITE) request_file=$< serial=9 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20000101121212 not_after=20300101121212 md=MD2 version=3 output_file=$@
all_final += cert_md2.crt

cert_md4.csr: $(cert_md_test_key)
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Cert MD4" md=MD4
all_intermediate += cert_md4.csr

cert_md4.crt: cert_md4.csr
	$(MBEDTLS_CERT_WRITE) request_file=$< serial=5 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20000101121212 not_after=20300101121212 md=MD4 version=3 output_file=$@
all_final += cert_md4.crt

cert_md5.csr: $(cert_md_test_key)
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< subject_name="C=NL,O=PolarSSL,CN=PolarSSL Cert MD5" md=MD5
all_intermediate += cert_md5.csr

cert_md5.crt: cert_md5.csr
	$(MBEDTLS_CERT_WRITE) request_file=$< serial=6 issuer_crt=$(test_ca_crt) issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) not_before=20000101121212 not_after=20300101121212 md=MD5 version=3 output_file=$@
all_final += cert_md5.crt

# - test-ca-v1.crt: v1 "CA", signs
#     server1-v1.crt: v1 "intermediate CA", signs
#         server2-v1*.crt: EE cert (without of with chain in same file)

test-ca-v1.crt: $(test_ca_key_file_rsa) test-ca.req.sha256
	$(MBEDTLS_CERT_WRITE) is_ca=1 serial=25883963888465069501131757029 \
		request_file=test-ca.req.sha256 \
		selfsign=1 issuer_name="CN=PolarSSL Test CA v1,OU=testing,O=PolarSSL,C=NL" \
		issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) \
		not_before=20190210144400 not_after=20290210144400 md=SHA256 version=1 \
		output_file=$@
all_final += test-ca-v1.crt

server1-v1.crt: server1.key test-ca-v1.crt
	$(MBEDTLS_CERT_WRITE) subject_key=$< serial=25883964939897181595909491649 \
		subject_name="CN=server1/int-ca-v1,OU=testing,O=PolarSSL,C=NL"  \
		issuer_crt=test-ca-v1.crt issuer_key=$(test_ca_key_file_rsa) \
		issuer_pwd=$(test_ca_pwd_rsa) \
		not_before=20190210144406 not_after=20290210144406 \
		md=SHA256 version=1 \
		output_file=$@
all_final += server1-v1.crt

server2-v1.crt: server2.key server1-v1.crt
	$(MBEDTLS_CERT_WRITE) subject_key=$< serial=25883965274140956871506900844 \
		subject_name="CN=server2,OU=testing,O=PolarSSL,C=NL"  \
		issuer_crt=server1-v1.crt issuer_key=server1.key \
		not_before=20190210144406 not_after=20290210144406 \
		md=SHA256 version=1 \
		output_file=$@
all_final += server2-v1.crt

server2-v1-chain.crt: server2-v1.crt server1-v1.crt
	cat $^ > $@

################################################################
#### Diffie-Hellman parameters
################################################################

dh.998.pem:
	$(OPENSSL) dhparam -out $@ -text 998

dh.999.pem:
	$(OPENSSL) dhparam -out $@ -text 999

################################################################
#### Meta targets
################################################################

all_final: $(all_final)
all: $(all_intermediate) $(all_final)

.PHONY: default all_final all
.PHONY: keys_rsa_all
.PHONY: keys_rsa_unenc keys_rsa_enc_basic
.PHONY: keys_rsa_enc_pkcs8_v1 keys_rsa_enc_pkcs8_v2
.PHONY: keys_rsa_enc_basic_1024 keys_rsa_enc_basic_2048 keys_rsa_enc_basic_4096
.PHONY: keys_rsa_enc_pkcs8_v1_1024 keys_rsa_enc_pkcs8_v2_1024
.PHONY: keys_rsa_enc_pkcs8_v1_2048 keys_rsa_enc_pkcs8_v2_2048
.PHONY: keys_rsa_enc_pkcs8_v1_4096 keys_rsa_enc_pkcs8_v2_4096
.PHONY: server1_all

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

.SECONDARY: $(all_intermediate)
