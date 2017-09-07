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

## Build the generated test data. Note that since the final outputs
## are committed to the repository, this target should do nothing on a
## fresh checkout. Furthermore, since the generation is randomized,
## re-running the same targets may result in differing files. The goal
## of this makefile is primarily to serve as a record of how the
## targets were generated in the first place.
default: all_final

all_intermediate := # temporary files
all_final := # files or targets used by tests



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
server2-sha256.crt: server2-rsa.csr
	$(OPENSSL) x509 -req -extfile $(cli_crt_extensions_file) -extensions cli-rsa -CA test-ca-sha256.crt -CAkey $(test_ca_key_file_rsa) -passin "pass:$(test_ca_pwd_rsa)" -set_serial 4 -days 3653 -sha256 -in server2-rsa.csr -out $@
all_final += server2-sha256.crt

################################################################
#### Generate various RSA keys
################################################################

### Password used for PKCS1-encoded encrypted RSA keys
keys_rsa_basic_pwd = testkey

### Password used for PKCS8-encoded encrypted RSA keys
keys_rsa_pkcs8_pwd = PolarSSLTest

### Basic 1024-, 2048- and 4096-bit unencrypted RSA keys from which
### all other encrypted RSA keys are derived.
keyfile_1024:
	$(OPENSSL) genrsa -out $@ 1024
keyfile_2048:
	$(OPENSSL) genrsa -out $@ 2048
keyfile_4096:
	$(OPENSSL) genrsa -out $@ 4096

###
### PKCS1-encoded, encrypted RSA keys
###

### 1024-bit
keyfile_1024.des: keyfile_1024
	$(OPENSSL) rsa -des -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keyfile_1024.3des: keyfile_1024
	$(OPENSSL) rsa -des3 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keyfile_1024.aes128: keyfile_1024
	$(OPENSSL) rsa -aes128 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keyfile_1024.aes192: keyfile_1024
	$(OPENSSL) rsa -aes192 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keyfile_1024.aes256: keyfile_1024
	$(OPENSSL) rsa -aes256 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keys_rsa_enc_basic_1024: keyfile_1024.des keyfile_1024.3des keyfile_1024.aes128 keyfile_1024.aes192 keyfile_1024.aes256

# 2048-bit
keyfile_2048.des: keyfile_2048
	$(OPENSSL) rsa -des -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keyfile_2048.3des: keyfile_2048
	$(OPENSSL) rsa -des3 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keyfile_2048.aes128: keyfile_2048
	$(OPENSSL) rsa -aes128 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keyfile_2048.aes192: keyfile_2048
	$(OPENSSL) rsa -aes192 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keyfile_2048.aes256: keyfile_2048
	$(OPENSSL) rsa -aes256 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keys_rsa_enc_basic_2048: keyfile_2048.des keyfile_2048.3des keyfile_2048.aes128 keyfile_2048.aes192 keyfile_2048.aes256

# 4096-bit
keyfile_4096.des: keyfile_4096
	$(OPENSSL) rsa -des -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keyfile_4096.3des: keyfile_4096
	$(OPENSSL) rsa -des3 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keyfile_4096.aes128: keyfile_4096
	$(OPENSSL) rsa -aes128 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keyfile_4096.aes192: keyfile_4096
	$(OPENSSL) rsa -aes192 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keyfile_4096.aes256: keyfile_4096
	$(OPENSSL) rsa -aes256 -in $< -out $@ -passout "pass:$(keys_rsa_basic_pwd)"
keys_rsa_enc_basic_4096: keyfile_4096.des keyfile_4096.3des keyfile_4096.aes128 keyfile_4096.aes192 keyfile_4096.aes256

###
### PKCS8-v1 encoded, encrypted RSA keys
###

### 1024-bit
pkcs8_pbe_sha1_3des_1024.der: keyfile_1024
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
pkcs8_pbe_sha1_3des_1024.key: keyfile_1024
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
keys_rsa_enc_pkcs8_v1_1024_3des: pkcs8_pbe_sha1_3des_1024.key pkcs8_pbe_sha1_3des_1024.der

pkcs8_pbe_sha1_2des_1024.der: keyfile_1024
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
pkcs8_pbe_sha1_2des_1024.key: keyfile_1024
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
keys_rsa_enc_pkcs8_v1_1024_2des: pkcs8_pbe_sha1_2des_1024.key pkcs8_pbe_sha1_2des_1024.der

pkcs8_pbe_sha1_rc4_128_1024.der: keyfile_1024
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-RC4-128
pkcs8_pbe_sha1_rc4_128_1024.key: keyfile_1024
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-RC4-128
keys_rsa_enc_pkcs8_v1_1024_rc4_128: pkcs8_pbe_sha1_rc4_128_1024.key pkcs8_pbe_sha1_rc4_128_1024.der

keys_rsa_enc_pkcs8_v1_1024: keys_rsa_enc_pkcs8_v1_1024_3des keys_rsa_enc_pkcs8_v1_1024_2des keys_rsa_enc_pkcs8_v1_1024_rc4_128

### 2048-bit
pkcs8_pbe_sha1_3des_2048.der: keyfile_2048
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
pkcs8_pbe_sha1_3des_2048.key: keyfile_2048
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
keys_rsa_enc_pkcs8_v1_2048_3des: pkcs8_pbe_sha1_3des_2048.key pkcs8_pbe_sha1_3des_2048.der

pkcs8_pbe_sha1_2des_2048.der: keyfile_2048
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
pkcs8_pbe_sha1_2des_2048.key: keyfile_2048
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
keys_rsa_enc_pkcs8_v1_2048_2des: pkcs8_pbe_sha1_2des_2048.key pkcs8_pbe_sha1_2des_2048.der

pkcs8_pbe_sha1_rc4_128_2048.der: keyfile_2048
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-RC4-128
pkcs8_pbe_sha1_rc4_128_2048.key: keyfile_2048
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-RC4-128
keys_rsa_enc_pkcs8_v1_2048_rc4_128: pkcs8_pbe_sha1_rc4_128_2048.key pkcs8_pbe_sha1_rc4_128_2048.der

keys_rsa_enc_pkcs8_v1_2048: keys_rsa_enc_pkcs8_v1_2048_3des keys_rsa_enc_pkcs8_v1_2048_2des keys_rsa_enc_pkcs8_v1_2048_rc4_128

### 4096-bit
pkcs8_pbe_sha1_3des_4096.der: keyfile_4096
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
pkcs8_pbe_sha1_3des_4096.key: keyfile_4096
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-3DES
keys_rsa_enc_pkcs8_v1_4096_3des: pkcs8_pbe_sha1_3des_4096.key pkcs8_pbe_sha1_3des_4096.der

pkcs8_pbe_sha1_2des_4096.der: keyfile_4096
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
pkcs8_pbe_sha1_2des_4096.key: keyfile_4096
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-2DES
keys_rsa_enc_pkcs8_v1_4096_2des: pkcs8_pbe_sha1_2des_4096.key pkcs8_pbe_sha1_2des_4096.der

pkcs8_pbe_sha1_rc4_128_4096.der: keyfile_4096
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-RC4-128
pkcs8_pbe_sha1_rc4_128_4096.key: keyfile_4096
	$(OPENSSL) pkcs8 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)" -topk8 -v1 PBE-SHA1-RC4-128
keys_rsa_enc_pkcs8_v1_4096_rc4_128: pkcs8_pbe_sha1_rc4_128_4096.key pkcs8_pbe_sha1_rc4_128_4096.der

keys_rsa_enc_pkcs8_v1_4096: keys_rsa_enc_pkcs8_v1_4096_3des keys_rsa_enc_pkcs8_v1_4096_2des keys_rsa_enc_pkcs8_v1_4096_rc4_128

###
### PKCS8-v2 encoded, encrypted RSA keys
###

### 1024-bit
pkcs8_pbes2_pbkdf2_3des_1024.der: keyfile_1024
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
pkcs8_pbes2_pbkdf2_3des_1024.key: keyfile_1024
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
keys_rsa_enc_pkcs8_v2_1024_3des: pkcs8_pbes2_pbkdf2_3des_1024.der pkcs8_pbes2_pbkdf2_3des_1024.key

pkcs8_pbes2_pbkdf2_des_1024.der: keyfile_1024
	$(OPENSSL) pkcs8 -topk8 -v2 des -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
pkcs8_pbes2_pbkdf2_des_1024.key: keyfile_1024
	$(OPENSSL) pkcs8  -topk8 -v2 des -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
keys_rsa_enc_pkcs8_v2_1024_des: pkcs8_pbes2_pbkdf2_des_1024.der pkcs8_pbes2_pbkdf2_des_1024.key

keys_rsa_enc_pkcs8_v2_1024: keys_rsa_enc_pkcs8_v2_1024_3des keys_rsa_enc_pkcs8_v2_1024_des

### 2048-bit
pkcs8_pbes2_pbkdf2_3des_2048.der: keyfile_2048
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
pkcs8_pbes2_pbkdf2_3des_2048.key: keyfile_2048
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
keys_rsa_enc_pkcs8_v2_2048_3des: pkcs8_pbes2_pbkdf2_3des_2048.der pkcs8_pbes2_pbkdf2_3des_2048.key

pkcs8_pbes2_pbkdf2_des_2048.der: keyfile_2048
	$(OPENSSL) pkcs8 -topk8 -v2 des -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
pkcs8_pbes2_pbkdf2_des_2048.key: keyfile_2048
	$(OPENSSL) pkcs8  -topk8 -v2 des -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
keys_rsa_enc_pkcs8_v2_2048_des: pkcs8_pbes2_pbkdf2_des_2048.der pkcs8_pbes2_pbkdf2_des_2048.key

keys_rsa_enc_pkcs8_v2_2048: keys_rsa_enc_pkcs8_v2_2048_3des keys_rsa_enc_pkcs8_v2_2048_des

### 4096-bit
pkcs8_pbes2_pbkdf2_3des_4096.der: keyfile_4096
	$(OPENSSL) pkcs8 -topk8 -v2 des3 -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
pkcs8_pbes2_pbkdf2_3des_4096.key: keyfile_4096
	$(OPENSSL) pkcs8  -topk8 -v2 des3 -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
keys_rsa_enc_pkcs8_v2_4096_3des: pkcs8_pbes2_pbkdf2_3des_4096.der pkcs8_pbes2_pbkdf2_3des_4096.key

pkcs8_pbes2_pbkdf2_des_4096.der: keyfile_4096
	$(OPENSSL) pkcs8 -topk8 -v2 des -inform PEM -in $< -outform DER -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
pkcs8_pbes2_pbkdf2_des_4096.key: keyfile_4096
	$(OPENSSL) pkcs8  -topk8 -v2 des -inform PEM -in $< -outform PEM -out $@ -passout "pass:$(keys_rsa_pkcs8_pwd)"
keys_rsa_enc_pkcs8_v2_4096_des: pkcs8_pbes2_pbkdf2_des_4096.der pkcs8_pbes2_pbkdf2_des_4096.key

keys_rsa_enc_pkcs8_v2_4096: keys_rsa_enc_pkcs8_v2_4096_3des keys_rsa_enc_pkcs8_v2_4096_des

###
### Rules to generate all RSA keys from a particular class
###

### Generate basic unencrypted RSA keys
keys_rsa_unenc: keyfile_1024 keyfile_2048 keyfile_4096

### Generate PKCS1-encoded encrypted RSA keys
keys_rsa_enc_basic: keys_rsa_enc_basic_1024 keys_rsa_enc_basic_2048 keys_rsa_enc_basic_4096

### Generate PKCS8-v1 encrypted RSA keys
keys_rsa_enc_pkcs8_v1: keys_rsa_enc_pkcs8_v1_1024 keys_rsa_enc_pkcs8_v1_2048 keys_rsa_enc_pkcs8_v1_4096

### Generate PKCS8-v2 encrypted RSA keys
keys_rsa_enc_pkcs8_v2: keys_rsa_enc_pkcs8_v2_1024 keys_rsa_enc_pkcs8_v2_2048 keys_rsa_enc_pkcs8_v2_4096

### Generate all RSA keys
keys_rsa_all: keys_rsa_unenc keys_rsa_enc_basic keys_rsa_enc_pkcs8_v1 keys_rsa_enc_pkcs8_v2

all_final += keys_rsa_all

################################################################
#### Meta targets
################################################################

all_final: $(all_final)
all: $(all_intermediate) $(all_final)

.PHONY: default all_final all keys_rsa_unenc keys_rsa_enc_basic keys_rsa_enc_pkcs8_v1 keys_rsa_enc_pkcs8_v2 keys_rsa_all keys_rsa_enc_basic_1024 keys_rsa_enc_basic_2048 keys_rsa_enc_basic_4096 keys_rsa_enc_pkcs8_v1_1024 keys_rsa_enc_pkcs8_v1_2048 keys_rsa_enc_pkcs8_v1_4096 keys_rsa_enc_pkcs8_v2_1024 keys_rsa_enc_pkcs8_v2_2048 keys_rsa_enc_pkcs8_v2_4096

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
