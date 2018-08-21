###########################################################################
#
#  Copyright (c) 2018, ARM Limited, All Rights Reserved
#  SPDX-License-Identifier: Apache-2.0
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
###########################################################################

#
# Use this file to export an Mbed Crypto release tarball as follows, from the
# top level of the mbedtls repo:
#
#   1) make -f scripts/mbed_crypto.make
#

.PHONY: all clean FORCE

all: mbedcrypto.tar.gz

#
# Crypto-necessary library files
#
LIB_FILES := \
	aes.c \
	aesni.c \
	arc4.c \
	asn1parse.c \
	asn1write.c \
	base64.c \
	bignum.c \
	blowfish.c \
	camellia.c \
	ccm.c \
	cipher.c \
	cipher_wrap.c \
	cmac.c \
	ctr_drbg.c \
	des.c \
	ecdsa.c \
	ecp.c \
	ecp_curves.c \
	entropy.c \
	entropy_poll.c \
	gcm.c \
	hmac_drbg.c \
	md.c \
	md2.c \
	md4.c \
	md5.c \
	md_wrap.c \
	oid.c \
	pem.c \
	pk.c \
	pk_wrap.c \
	pkcs12.c \
	pkcs5.c \
	pkparse.c \
	pkwrite.c \
	platform.c \
	platform_util.c \
	psa_crypto.c \
	ripemd160.c \
	rsa_internal.c \
	rsa.c \
	sha1.c \
	sha256.c \
	sha512.c \
	xtea.c \
# Don't delete this line.

#
# Crypto-necessary include files
#
INC_FILES := \
	mbedcrypto/aes.h \
	mbedcrypto/aesni.h \
	mbedcrypto/arc4.h \
	mbedcrypto/asn1.h \
	mbedcrypto/asn1write.h \
	mbedcrypto/base64.h \
	mbedcrypto/bignum.h \
	mbedcrypto/blowfish.h \
	mbedcrypto/bn_mul.h \
	mbedcrypto/camellia.h \
	mbedcrypto/ccm.h \
	mbedcrypto/certs.h \
	mbedcrypto/check_config.h \
	mbedcrypto/cipher.h \
	mbedcrypto/cipher_internal.h \
	mbedcrypto/cmac.h \
	mbedcrypto/config.h \
	mbedcrypto/ctr_drbg.h \
	mbedcrypto/des.h \
	mbedcrypto/ecdsa.h \
	mbedcrypto/ecp.h \
	mbedcrypto/ecp_internal.h \
	mbedcrypto/entropy.h \
	mbedcrypto/entropy_poll.h \
	mbedcrypto/error.h \
	mbedcrypto/gcm.h \
	mbedcrypto/hmac_drbg.h \
	mbedcrypto/md.h \
	mbedcrypto/md2.h \
	mbedcrypto/md4.h \
	mbedcrypto/md5.h \
	mbedcrypto/md_internal.h \
	mbedcrypto/oid.h \
	mbedcrypto/pem.h \
	mbedcrypto/pk.h \
	mbedcrypto/pk_internal.h \
	mbedcrypto/pkcs11.h \
	mbedcrypto/pkcs12.h \
	mbedcrypto/pkcs5.h \
	mbedcrypto/platform.h \
	mbedcrypto/platform_util.h \
	mbedcrypto/ripemd160.h \
	mbedcrypto/rsa.h \
	mbedcrypto/rsa_internal.h \
	mbedcrypto/sha1.h \
	mbedcrypto/sha256.h \
	mbedcrypto/sha512.h \
	mbedcrypto/threading.h \
	mbedcrypto/xtea.h \
	psa/crypto.h \
	psa/crypto_extra.h \
	psa/crypto_platform.h \
	psa/crypto_sizes.h \
	psa/crypto_struct.h \
# Don't delete this line.

TEST_FILES := \
	tests/scripts/generate_test_code.py \
	tests/scripts/mbedtls_test.py \
	tests/scripts/test_generate_test_code.py \
	tests/scripts/run-test-suites.pl \
	tests/suites/helpers.function \
	tests/suites/host_test.function \
	tests/suites/main_test.function \
	tests/suites/target_test.function \
	tests/suites/test_suite_psa_crypto.data \
	tests/suites/test_suite_psa_crypto.function \
	tests/suites/test_suite_psa_crypto_metadata.data \
	tests/suites/test_suite_psa_crypto_metadata.function \
# Don't delete this line.

OTHER_FILES := \
	LICENSE \
	VERSION.txt \
	programs/psa/crypto_examples.c \
	programs/psa/key_ladder_demo.c \
	programs/psa/key_ladder_demo.sh \
	programs/psa/psa_constant_names.c \
	scripts/config.pl \
	scripts/generate_psa_constants.py \
# Don't delete this line.

# Prepend destination directory
LIB_FILES := $(addprefix crypto/library/,$(LIB_FILES))
INC_FILES := $(addprefix crypto/include/,$(INC_FILES))
TEST_FILES := $(addprefix crypto/,$(TEST_FILES))
OTHER_FILES := $(addprefix crypto/,$(OTHER_FILES))

define rename_mbedcrypto
	@sed -i -e 's/Mbed TLS/Mbed Crypto/g' $(1)
	@sed -i -e 's/mbed TLS/Mbed Crypto/g' $(1)
	@sed -i -e 's/MBEDTLS_/MBEDCRYPTO_/g' $(1)
	@sed -i -e 's/mbedtls/mbedcrypto/g' $(1)
	@sed -i -e 's/MbedTls/MbedCrypto/g' $(1)
	@sed -i -e 's/include\/mbedtls/include\/mbedcrypto/g' $(1)
endef

crypto/include/mbedcrypto/config.h: configs/config-psa-crypto.h
	@echo $@
	@mkdir -p $(dir $@)
	@cp $< $@
	@#Rename the file in the comments
	@sed -i -e 's/config-psa-crypto.h/config.h/g' $@
	$(call rename_mbedcrypto,$@)

crypto/tests/data_files/%: tests/data_files/%
	@echo $@
	@mkdir -p $(dir $@)
	@cp $< $@
	@#Don't rename things inside data files

crypto/include/mbedcrypto/%.h: include/mbedtls/%.h
	@echo $@
	@mkdir -p $(dir $@)
	@cp $< $@
	$(call rename_mbedcrypto,$@)

crypto/LICENSE: apache-2.0.txt
	@echo $@
	@mkdir -p $(dir $@)
	@cp $< $@
	@#Don't rename anything in the license

crypto/%: %
	@echo $@
	@mkdir -p $(dir $@)
	@cp $< $@
	$(call rename_mbedcrypto,$@)

crypto/VERSION.txt: FORCE
	@git describe --tags --abbrev=12 --dirty > $@

mbedcrypto.tar.gz: $(LIB_FILES) $(INC_FILES) $(TEST_FILES) $(OTHER_FILES)
	@echo $@
	@tar czf mbedcrypto.tar.gz crypto

clean:
	@echo clean
	@rm -rf mbedcrypto.tar.gz \
		$(LIB_FILES) $(INC_FILES) $(TEST_FILES) $(OTHER_FILES)

FORCE:

# vi: ft=make
