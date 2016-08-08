
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile with PKCS11: add "-lpkcs11-helper" to LDFLAGS

CFLAGS	?= -O2
WARNING_CFLAGS ?= -Wall -W -Wdeclaration-after-statement -Wno-unused-function -Wno-unused-value
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = -L../library 			\
		-lmbedtls$(SHARED_SUFFIX)	\
		-lmbedx509$(SHARED_SUFFIX)	\
		-lmbedcrypto$(SHARED_SUFFIX)

ifdef MBED_TEST
    GEN_CODE_OPTS=--mbed --mainfile suites/main_test_mbed.function
    SRCEXT=.cpp
else
    GEN_CODE_OPTS=
    SRCEXT=.c
endif

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
DLEXT=so
EXEXT=
SHARED_SUFFIX=
endif

# Zlib shared library extensions:
ifdef ZLIB
LOCAL_LDFLAGS += -lz
endif

TEST_SUITES = test_suite_aes.ecb \
	test_suite_aes.cbc\
	test_suite_aes.cfb \
	test_suite_aes.rest \
	test_suite_arc4 \
	test_suite_asn1write \
	test_suite_base64 \
	test_suite_blowfish \
	test_suite_camellia \
	test_suite_ccm \
	test_suite_cipher.aes \
	test_suite_cipher.arc4 \
	test_suite_cipher.ccm \
	test_suite_cipher.gcm \
	test_suite_cipher.blowfish \
	test_suite_cipher.camellia \
	test_suite_cipher.des \
	test_suite_cipher.null \
	test_suite_cipher.padding \
	test_suite_ctr_drbg \
	test_suite_debug \
	test_suite_des \
    test_suite_dhm \
	test_suite_ecdh \
	test_suite_ecdsa \
	test_suite_ecjpake \
	test_suite_ecp \
	test_suite_error \
	test_suite_entropy \
	test_suite_gcm.aes128_de \
	test_suite_gcm.aes192_de \
	test_suite_gcm.aes256_de \
	test_suite_gcm.aes128_en \
	test_suite_gcm.aes192_en \
	test_suite_gcm.aes256_en \
	test_suite_gcm.camellia \
	test_suite_hmac_drbg.misc \
	test_suite_hmac_drbg.no_reseed \
	test_suite_hmac_drbg.nopr \
	test_suite_hmac_drbg.pr \
	test_suite_md \
	test_suite_mdx \
	test_suite_memory_buffer_alloc \
	test_suite_mpi  \
	test_suite_pem \
	test_suite_pkcs1_v15 \
	test_suite_pkcs1_v21 \
	test_suite_pkcs5 \
	test_suite_pkparse \
	test_suite_pkwrite \
	test_suite_pk \
	test_suite_rsa \
	test_suite_shax \
	test_suite_ssl \
	test_suite_x509parse \
	test_suite_x509write \
	test_suite_xtea \
	test_suite_version

APPS = $(addsuffix $(EXEXT),$(TEST_SUITES))

APPS_SRC = $(addsuffix $(SRCEXT),$(TEST_SUITES))

.SILENT:

.PHONY: all check test clean

all: $(APPS)

$(DEP):
	$(MAKE) -C ../library

# invoke perl explicitly for the sake of mingw32-make

test_suite_aes.ecb$(SRCEXT) : suites/test_suite_aes.function suites/test_suite_aes.ecb.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_aes --dataname test_suite_aes.ecb $(GEN_CODE_OPTS)

test_suite_aes.cbc$(SRCEXT) : suites/test_suite_aes.function suites/test_suite_aes.cbc.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_aes --dataname test_suite_aes.cbc $(GEN_CODE_OPTS)

test_suite_aes.cfb$(SRCEXT) : suites/test_suite_aes.function suites/test_suite_aes.cfb.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_aes --dataname test_suite_aes.cfb $(GEN_CODE_OPTS)

test_suite_aes.rest$(SRCEXT) : suites/test_suite_aes.function suites/test_suite_aes.rest.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_aes --dataname test_suite_aes.rest $(GEN_CODE_OPTS)

test_suite_cipher.aes$(SRCEXT) : suites/test_suite_cipher.function suites/test_suite_cipher.aes.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_cipher --dataname test_suite_cipher.aes $(GEN_CODE_OPTS)

test_suite_cipher.arc4$(SRCEXT) : suites/test_suite_cipher.function suites/test_suite_cipher.arc4.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_cipher --dataname test_suite_cipher.arc4 $(GEN_CODE_OPTS)

test_suite_cipher.ccm$(SRCEXT) : suites/test_suite_cipher.function suites/test_suite_cipher.ccm.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_cipher --dataname test_suite_cipher.ccm $(GEN_CODE_OPTS)

test_suite_cipher.gcm$(SRCEXT) : suites/test_suite_cipher.function suites/test_suite_cipher.gcm.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_cipher --dataname test_suite_cipher.gcm $(GEN_CODE_OPTS)

test_suite_cipher.blowfish$(SRCEXT) : suites/test_suite_cipher.function suites/test_suite_cipher.blowfish.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_cipher --dataname test_suite_cipher.blowfish $(GEN_CODE_OPTS)

test_suite_cipher.camellia$(SRCEXT) : suites/test_suite_cipher.function suites/test_suite_cipher.camellia.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_cipher --dataname test_suite_cipher.camellia $(GEN_CODE_OPTS)

test_suite_cipher.des$(SRCEXT) : suites/test_suite_cipher.function suites/test_suite_cipher.des.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_cipher --dataname test_suite_cipher.des $(GEN_CODE_OPTS)

test_suite_cipher.null$(SRCEXT) : suites/test_suite_cipher.function suites/test_suite_cipher.null.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_cipher --dataname test_suite_cipher.null $(GEN_CODE_OPTS)

test_suite_cipher.padding$(SRCEXT) : suites/test_suite_cipher.function suites/test_suite_cipher.padding.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_cipher --dataname test_suite_cipher.padding $(GEN_CODE_OPTS)

test_suite_gcm.aes128_de$(SRCEXT) : suites/test_suite_gcm.function suites/test_suite_gcm.aes128_de.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_gcm --dataname test_suite_gcm.aes128_de $(GEN_CODE_OPTS)

test_suite_gcm.aes192_de$(SRCEXT) : suites/test_suite_gcm.function suites/test_suite_gcm.aes192_de.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_gcm --dataname test_suite_gcm.aes192_de $(GEN_CODE_OPTS)

test_suite_gcm.aes256_de$(SRCEXT) : suites/test_suite_gcm.function suites/test_suite_gcm.aes256_de.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_gcm --dataname test_suite_gcm.aes256_de $(GEN_CODE_OPTS)

test_suite_gcm.aes128_en$(SRCEXT) : suites/test_suite_gcm.function suites/test_suite_gcm.aes128_en.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_gcm --dataname test_suite_gcm.aes128_en $(GEN_CODE_OPTS)

test_suite_gcm.aes192_en$(SRCEXT) : suites/test_suite_gcm.function suites/test_suite_gcm.aes192_en.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_gcm --dataname test_suite_gcm.aes192_en $(GEN_CODE_OPTS)

test_suite_gcm.aes256_en$(SRCEXT) : suites/test_suite_gcm.function suites/test_suite_gcm.aes256_en.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_gcm --dataname test_suite_gcm.aes256_en $(GEN_CODE_OPTS)

test_suite_gcm.camellia$(SRCEXT) : suites/test_suite_gcm.function suites/test_suite_gcm.camellia.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_gcm --dataname test_suite_gcm.camellia $(GEN_CODE_OPTS)

test_suite_hmac_drbg.misc$(SRCEXT) : suites/test_suite_hmac_drbg.function suites/test_suite_hmac_drbg.misc.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_hmac_drbg --dataname test_suite_hmac_drbg.misc $(GEN_CODE_OPTS)

test_suite_hmac_drbg.no_reseed$(SRCEXT) : suites/test_suite_hmac_drbg.function suites/test_suite_hmac_drbg.no_reseed.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_hmac_drbg --dataname test_suite_hmac_drbg.no_reseed $(GEN_CODE_OPTS)

test_suite_hmac_drbg.nopr$(SRCEXT) : suites/test_suite_hmac_drbg.function suites/test_suite_hmac_drbg.nopr.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_hmac_drbg --dataname test_suite_hmac_drbg.nopr $(GEN_CODE_OPTS)

test_suite_hmac_drbg.pr$(SRCEXT) : suites/test_suite_hmac_drbg.function suites/test_suite_hmac_drbg.pr.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename test_suite_hmac_drbg --dataname test_suite_hmac_drbg.pr $(GEN_CODE_OPTS)

%$(SRCEXT) : suites/%.function suites/%.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo "  Gen   $@"
	perl scripts/generate_code.pl --suitedir suites --suitename $* --dataname $* $(GEN_CODE_OPTS)

test_suite_aes.ecb$(EXEXT): test_suite_aes.ecb.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_aes.cbc$(EXEXT): test_suite_aes.cbc.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_aes.cfb$(EXEXT): test_suite_aes.cfb.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_aes.rest$(EXEXT): test_suite_aes.rest.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_arc4$(EXEXT): test_suite_arc4.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_asn1write$(EXEXT): test_suite_asn1write.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_base64$(EXEXT): test_suite_base64.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_blowfish$(EXEXT): test_suite_blowfish.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_camellia$(EXEXT): test_suite_camellia.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_ccm$(EXEXT): test_suite_ccm.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_cipher.aes$(EXEXT): test_suite_cipher.aes.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_cipher.arc4$(EXEXT): test_suite_cipher.arc4.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_cipher.ccm$(EXEXT): test_suite_cipher.ccm.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_cipher.gcm$(EXEXT): test_suite_cipher.gcm.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_cipher.blowfish$(EXEXT): test_suite_cipher.blowfish.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_cipher.camellia$(EXEXT): test_suite_cipher.camellia.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_cipher.des$(EXEXT): test_suite_cipher.des.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_cipher.null$(EXEXT): test_suite_cipher.null.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_cipher.padding$(EXEXT): test_suite_cipher.padding.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_ctr_drbg$(EXEXT): test_suite_ctr_drbg.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_des$(EXEXT): test_suite_des.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_dhm$(EXEXT): test_suite_dhm.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_ecdh$(EXEXT): test_suite_ecdh.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_ecdsa$(EXEXT): test_suite_ecdsa.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_ecjpake$(EXEXT): test_suite_ecjpake.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_ecp$(EXEXT): test_suite_ecp.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_entropy$(EXEXT): test_suite_entropy.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_error$(EXEXT): test_suite_error.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_gcm.aes128_de$(EXEXT): test_suite_gcm.aes128_de.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_gcm.aes192_de$(EXEXT): test_suite_gcm.aes192_de.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_gcm.aes256_de$(EXEXT): test_suite_gcm.aes256_de.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_gcm.aes128_en$(EXEXT): test_suite_gcm.aes128_en.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_gcm.aes192_en$(EXEXT): test_suite_gcm.aes192_en.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_gcm.aes256_en$(EXEXT): test_suite_gcm.aes256_en.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_gcm.camellia$(EXEXT): test_suite_gcm.camellia.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_hmac_drbg.misc$(EXEXT): test_suite_hmac_drbg.misc.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_hmac_drbg.no_reseed$(EXEXT): test_suite_hmac_drbg.no_reseed.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_hmac_drbg.nopr$(EXEXT): test_suite_hmac_drbg.nopr.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_hmac_drbg.pr$(EXEXT): test_suite_hmac_drbg.pr.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_md$(EXEXT): test_suite_md.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_mdx$(EXEXT): test_suite_mdx.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_memory_buffer_alloc$(EXEXT): test_suite_memory_buffer_alloc.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_mpi$(EXEXT): test_suite_mpi.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_pbkdf2$(EXEXT): test_suite_pbkdf2.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_pem$(EXEXT): test_suite_pem.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_pkcs1_v15$(EXEXT): test_suite_pkcs1_v15.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_pkcs1_v21$(EXEXT): test_suite_pkcs1_v21.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_pkcs5$(EXEXT): test_suite_pkcs5.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_pkparse$(EXEXT): test_suite_pkparse.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_pkwrite$(EXEXT): test_suite_pkwrite.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_pk$(EXEXT): test_suite_pk.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_rsa$(EXEXT): test_suite_rsa.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_shax$(EXEXT): test_suite_shax.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_ssl$(EXEXT): test_suite_ssl.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_x509parse$(EXEXT): test_suite_x509parse.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_x509write$(EXEXT): test_suite_x509write.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_xtea$(EXEXT): test_suite_xtea.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_debug$(EXEXT): test_suite_debug.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test_suite_version$(EXEXT): test_suite_version.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

clean:
ifndef WINDOWS
	rm -f $(APPS) *.c *.cpp
else
	del /Q /F *.c *.exe
endif

check: $(APPS)
	perl scripts/run-test-suites.pl

test: check

gen_test_code: $(APPS_SRC)
