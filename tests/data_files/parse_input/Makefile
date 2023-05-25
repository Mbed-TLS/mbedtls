## This file contains a record of how the parse test input data was
## generated. The final build products are committed to the repository
## as well to make sure that the test data is identical. You do not
## need to use this makefile unless you're extending mbed TLS's parse tests.

## NOTE: that in addition to depending on the version of the data generation
##       tool, many of the build outputs are randomized, so running this
##       makefile twice would not produce the same results.
##
## WARNING: FOR TIME BEING, WE CAN NOT GUARANTEE IT WORKS CORRECTLY
##

## Tools
OPENSSL ?= openssl
FAKETIME ?= faketime

TOP_DIR = ../../..
MBEDTLS_CERT_WRITE ?= $(TOP_DIR)/programs/x509/cert_write
MBEDTLS_CERT_REQ ?= $(TOP_DIR)/programs/x509/cert_req

all_intermediate := # temporary files
all_final := # files used by tests

.DEFAULT: all

################################################################
#### Generate files rulers
################################################################

test_ca_crt = test-ca.crt
test_ca_key_file_rsa = test-ca.key
test_ca_pwd_rsa = PolarSSLTest

cli_crt_key_file_rsa = cli-rsa.key

cli-rsa.csr: $(cli_crt_key_file_rsa)
	$(MBEDTLS_CERT_REQ) output_file=$@ filename=$< \
		subject_name="C=NL,O=PolarSSL,CN=PolarSSL Client 2" md=SHA1
all_intermediate += cli-rsa.csr

cli-rsa-sha256.crt: cli-rsa.csr
	$(MBEDTLS_CERT_WRITE) request_file=$< serial=4 issuer_crt=$(test_ca_crt) \
	issuer_key=$(test_ca_key_file_rsa) issuer_pwd=$(test_ca_pwd_rsa) \
	not_before=20190210144406 not_after=20290210144406 \
	md=SHA256 version=3 output_file=$@
all_intermediate += cli-rsa-sha256.crt

cli-rsa-sha256.crt.der: cli-rsa-sha256.crt
	$(OPENSSL) x509 -in $< -out $@ -inform PEM -outform DER
all_intermediate += cli-rsa-sha256.crt.der

cli-rsa-sha256-badalg.crt.der: cli-rsa-sha256.crt.der
	hexdump -ve '1/1 "%.2X"' $< | sed "s/06092A864886F70D01010B0500/06092A864886F70D01010B0900/2" | xxd -r -p > $@
all_final += cli-rsa-sha256-badalg.crt.der

################################################################
#### Meta targets
################################################################

# These files should not be committed to the repository.
list_intermediate:
	@printf '%s\n' $(all_intermediate) | sort

# These files should be committed to the repository so that the test data is
# available upon checkout without running a randomized process depending on
# third-party tools.
list_final:
	@printf '%s\n' $(all_final) | sort

## Remove intermediate files
clean:
	rm -f $(all_intermediate)

## Remove all build products, even the ones that are committed
neat: clean
	rm -f $(all_final)

.PHONY: list_intermediate list_final
.PHONY: clean neat all
.INTERMEDIATE: $(all_intermediate)

all:$(all_final)
