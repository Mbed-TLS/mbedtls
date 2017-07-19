
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile with PKCS11: add "-lpkcs11-helper" to LDFLAGS

CFLAGS	?= -O2
WARNING_CFLAGS ?= -Wall -W -Wdeclaration-after-statement -Wno-unused-function -Wno-unused-value
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = -L../library			\
		-lmbedtls$(SHARED_SUFFIX)	\
		-lmbedx509$(SHARED_SUFFIX)	\
		-lmbedcrypto$(SHARED_SUFFIX)

ifndef SHARED
DEP=../library/libmbedcrypto.a ../library/libmbedx509.a ../library/libmbedtls.a
else
DEP=../library/libmbedcrypto.$(DLEXT) ../library/libmbedx509.$(DLEXT) ../library/libmbedtls.$(DLEXT)
endif

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

# if we're running on Windows, build for Windows
ifdef WINDOWS
WINDOWS_BUILD=1
endif

ifdef WINDOWS_BUILD
DLEXT=dll
EXEXT=.exe
LOCAL_LDFLAGS += -lws2_32
ifdef SHARED
SHARED_SUFFIX=.$(DLEXT)
endif
else
DLEXT ?= so
EXEXT=
SHARED_SUFFIX=
endif

# Zlib shared library extensions:
ifdef ZLIB
LOCAL_LDFLAGS += -lz
endif

APPS =	test_suite_aes.ecb	test_suite_aes.cbc	\
	test_suite_aes.cfb	test_suite_aes.rest	\
	test_suite_arc4		test_suite_asn1write	\
	test_suite_base64	test_suite_blowfish	\
	test_suite_camellia	test_suite_ccm		\
	test_suite_cipher.aes					\
	test_suite_cipher.arc4	test_suite_cipher.ccm	\
	test_suite_cipher.gcm					\
	test_suite_cipher.blowfish				\
	test_suite_cipher.camellia				\
	test_suite_cipher.des	test_suite_cipher.null	\
	test_suite_cipher.padding				\
	test_suite_ctr_drbg	test_suite_debug	\
	test_suite_des		test_suite_dhm		\
	test_suite_ecdh		test_suite_ecdsa	\
	test_suite_ecp						\
	test_suite_error	test_suite_entropy	\
	test_suite_gcm.aes128_de				\
	test_suite_gcm.aes192_de				\
	test_suite_gcm.aes256_de				\
	test_suite_gcm.aes128_en				\
	test_suite_gcm.aes192_en				\
	test_suite_gcm.aes256_en				\
	test_suite_gcm.camellia					\
	test_suite_hmac_drbg.misc				\
	test_suite_hmac_drbg.no_reseed				\
	test_suite_hmac_drbg.nopr				\
	test_suite_hmac_drbg.pr					\
	test_suite_md		test_suite_mdx		\
	test_suite_memory_buffer_alloc				\
	test_suite_mpi						\
	test_suite_pem						\
	test_suite_pkcs1_v21	test_suite_pkcs5	\
	test_suite_pkparse	test_suite_pkwrite	\
	test_suite_pk						\
	test_suite_rsa		test_suite_shax		\
	test_suite_ssl						\
	test_suite_x509parse	test_suite_x509write	\
	test_suite_xtea		test_suite_version

BINARIES := $(addsuffix $(EXEXT),$(APPS))

# Look up for associated function files
func.test_suite_aes.ecb := test_suite_aes
func.test_suite_aes.cbc := test_suite_aes
func.test_suite_aes.cfb := test_suite_aes
func.test_suite_aes.rest := test_suite_aes
func.test_suite_arc4 := test_suite_arc4
func.test_suite_asn1write := test_suite_asn1write
func.test_suite_base64 := test_suite_base64
func.test_suite_blowfish := test_suite_blowfish
func.test_suite_camellia := test_suite_camellia
func.test_suite_ccm := test_suite_ccm
func.test_suite_cipher.aes := test_suite_cipher
func.test_suite_cipher.arc4 := test_suite_cipher
func.test_suite_cipher.ccm := test_suite_cipher
func.test_suite_cipher.gcm := test_suite_cipher
func.test_suite_cipher.blowfish := test_suite_cipher
func.test_suite_cipher.camellia := test_suite_cipher
func.test_suite_cipher.des := test_suite_cipher
func.test_suite_cipher.null := test_suite_cipher
func.test_suite_cipher.padding := test_suite_cipher
func.test_suite_ctr_drbg := test_suite_ctr_drbg
func.test_suite_debug := test_suite_debug
func.test_suite_des := test_suite_des
func.test_suite_dhm := test_suite_dhm
func.test_suite_ecdh := test_suite_ecdh
func.test_suite_ecdsa := test_suite_ecdsa
func.test_suite_ecp := test_suite_ecp
func.test_suite_error := test_suite_error
func.test_suite_entropy := test_suite_entropy
func.test_suite_gcm.aes128_de := test_suite_gcm
func.test_suite_gcm.aes192_de := test_suite_gcm
func.test_suite_gcm.aes256_de := test_suite_gcm
func.test_suite_gcm.aes128_en := test_suite_gcm
func.test_suite_gcm.aes192_en := test_suite_gcm
func.test_suite_gcm.aes256_en := test_suite_gcm
func.test_suite_gcm.camellia := test_suite_gcm
func.test_suite_hmac_drbg.misc := test_suite_hmac_drbg
func.test_suite_hmac_drbg.no_reseed := test_suite_hmac_drbg
func.test_suite_hmac_drbg.nopr := test_suite_hmac_drbg
func.test_suite_hmac_drbg.pr := test_suite_hmac_drbg
func.test_suite_md := test_suite_md
func.test_suite_mdx := test_suite_mdx
func.test_suite_memory_buffer_alloc := test_suite_memory_buffer_alloc
func.test_suite_mpi := test_suite_mpi
func.test_suite_pem := test_suite_pem
func.test_suite_pkcs1_v21 := test_suite_pkcs1_v21
func.test_suite_pkcs5 := test_suite_pkcs5
func.test_suite_pkparse := test_suite_pkparse
func.test_suite_pkwrite := test_suite_pkwrite
func.test_suite_pk := test_suite_pk
func.test_suite_rsa := test_suite_rsa
func.test_suite_shax := test_suite_shax
func.test_suite_ssl := test_suite_ssl
func.test_suite_x509parse := test_suite_x509parse
func.test_suite_x509write := test_suite_x509write
func.test_suite_xtea := test_suite_xtea
func.test_suite_version := test_suite_version

.SILENT:

.PHONY: all check test clean

all: $(BINARIES)

$(DEP):
	$(MAKE) -C ../library

# invoke perl explicitly for the sake of mingw32-make

C_FILES := $(addsuffix .c,$(APPS))

.SECONDEXPANSION:
$(C_FILES): %.c: suites/$$(func.$$*).function suites/%.data scripts/generate_code.py suites/helpers.function suites/main_test.function suites/host_test.function
	echo "  Gen   $@"
	python scripts/generate_code.py -f suites/$(func.$*).function \
		-d suites/$*.data \
		-t suites/main_test.function \
		-p suites/host_test.function \
		-s suites  \
		--help-file suites/helpers.function \
		-o .


$(BINARIES): %$(EXEXT): %.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@


clean:
ifndef WINDOWS
	rm -rf $(APPS) *.c *.data TESTS
else
	del /Q /F *.c *.exe *.data
	rmdir /Q /S TESTS
endif

check: $(BINARIES)
	perl scripts/run-test-suites.pl

test: check

# Create separate targets for generating embedded tests.
EMBEDDED_TESTS := $(addprefix embedded_,$(APPS))

# Generate test code for target.

.SECONDEXPANSION:
$(EMBEDDED_TESTS): embedded_%: suites/$$(func.$$*).function suites/%.data scripts/generate_code.py suites/helpers.function suites/main_test.function suites/target_test.function
	echo "  Gen  ./TESTS/mbedtls/$*/$*.c"
	python scripts/generate_code.py -f suites/$(func.$*).function \
		-d suites/$*.data \
		-t suites/main_test.function \
		-p suites/target_test.function \
		-s suites  \
		--help-file suites/helpers.function \
		-o ./TESTS/mbedtls/$*

gen-embedded-test: $(EMBEDDED_TESTS)

