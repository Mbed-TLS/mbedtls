
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile on MinGW: add "-lws2_32" to LDFLAGS or define WINDOWS in your env
# To compile with PKCS11: add "-lpkcs11-helper" to LDFLAGS

CFLAGS	+= -I../include -D_FILE_OFFSET_BITS=64 -Wall -W -Wdeclaration-after-statement \
			-Wno-unused-function -Wno-unused-value

OFLAGS	= -O2
LDFLAGS	+= -L../library -lpolarssl $(SYS_LDFLAGS)

ifndef SHARED
DEP=../library/libpolarssl.a
CHECK_PRELOAD=
else
DEP=../library/libpolarssl.so
CHECK_PRELOAD= LD_PRELOAD=../library/libpolarssl.so
endif

ifdef DEBUG
CFLAGS += -g3
endif

ifdef WINDOWS
LDFLAGS += -lws2_32
endif

# Zlib shared library extensions:
ifdef ZLIB
LDFLAGS += -lz
endif

APPS =	test_suite_aes.ecb		test_suite_aes.cbc		\
		test_suite_aes.cfb		test_suite_aes.rest		\
		test_suite_arc4			test_suite_asn1write	\
		test_suite_base64		test_suite_blowfish		\
		test_suite_camellia		test_suite_ccm			\
		test_suite_cipher.aes							\
		test_suite_cipher.arc4	test_suite_cipher.ccm	\
		test_suite_cipher.gcm							\
		test_suite_cipher.blowfish						\
		test_suite_cipher.camellia						\
		test_suite_cipher.des	test_suite_cipher.null	\
		test_suite_cipher.padding						\
		test_suite_ctr_drbg		test_suite_debug		\
		test_suite_des			test_suite_dhm			\
		test_suite_ecdh			test_suite_ecdsa		\
		test_suite_ecp									\
		test_suite_error		test_suite_entropy		\
		test_suite_gcm.aes128_de						\
		test_suite_gcm.aes192_de						\
		test_suite_gcm.aes256_de						\
		test_suite_gcm.aes128_en						\
		test_suite_gcm.aes192_en						\
		test_suite_gcm.aes256_en						\
		test_suite_gcm.camellia	test_suite_hmac_shax	\
		test_suite_hmac_drbg.misc						\
		test_suite_hmac_drbg.no_reseed					\
		test_suite_hmac_drbg.nopr						\
		test_suite_hmac_drbg.pr							\
		test_suite_md			test_suite_mdx			\
		test_suite_mpi			test_suite_pbkdf2		\
		test_suite_pem									\
		test_suite_pkcs1_v21	test_suite_pkcs5		\
		test_suite_pkparse		test_suite_pkwrite		\
		test_suite_pk									\
		test_suite_rsa			test_suite_shax			\
		test_suite_x509parse	test_suite_x509write	\
		test_suite_xtea			test_suite_version

.SILENT:

all: $(APPS)

test_suite_aes.ecb.c : suites/test_suite_aes.function suites/test_suite_aes.ecb.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_aes test_suite_aes.ecb

test_suite_aes.cbc.c : suites/test_suite_aes.function suites/test_suite_aes.cbc.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_aes test_suite_aes.cbc

test_suite_aes.cfb.c : suites/test_suite_aes.function suites/test_suite_aes.cfb.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_aes test_suite_aes.cfb

test_suite_aes.rest.c : suites/test_suite_aes.function suites/test_suite_aes.rest.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_aes test_suite_aes.rest

test_suite_cipher.aes.c : suites/test_suite_cipher.function suites/test_suite_cipher.aes.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_cipher test_suite_cipher.aes

test_suite_cipher.arc4.c : suites/test_suite_cipher.function suites/test_suite_cipher.arc4.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_cipher test_suite_cipher.arc4

test_suite_cipher.ccm.c : suites/test_suite_cipher.function suites/test_suite_cipher.ccm.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_cipher test_suite_cipher.ccm

test_suite_cipher.gcm.c : suites/test_suite_cipher.function suites/test_suite_cipher.gcm.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_cipher test_suite_cipher.gcm

test_suite_cipher.blowfish.c : suites/test_suite_cipher.function suites/test_suite_cipher.blowfish.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_cipher test_suite_cipher.blowfish

test_suite_cipher.camellia.c : suites/test_suite_cipher.function suites/test_suite_cipher.camellia.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_cipher test_suite_cipher.camellia

test_suite_cipher.des.c : suites/test_suite_cipher.function suites/test_suite_cipher.des.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_cipher test_suite_cipher.des

test_suite_cipher.null.c : suites/test_suite_cipher.function suites/test_suite_cipher.null.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_cipher test_suite_cipher.null

test_suite_cipher.padding.c : suites/test_suite_cipher.function suites/test_suite_cipher.padding.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_cipher test_suite_cipher.padding

test_suite_gcm.aes128_de.c : suites/test_suite_gcm.function suites/test_suite_gcm.aes128_de.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_gcm test_suite_gcm.aes128_de

test_suite_gcm.aes192_de.c : suites/test_suite_gcm.function suites/test_suite_gcm.aes192_de.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_gcm test_suite_gcm.aes192_de

test_suite_gcm.aes256_de.c : suites/test_suite_gcm.function suites/test_suite_gcm.aes256_de.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_gcm test_suite_gcm.aes256_de

test_suite_gcm.aes128_en.c : suites/test_suite_gcm.function suites/test_suite_gcm.aes128_en.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_gcm test_suite_gcm.aes128_en

test_suite_gcm.aes192_en.c : suites/test_suite_gcm.function suites/test_suite_gcm.aes192_en.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_gcm test_suite_gcm.aes192_en

test_suite_gcm.aes256_en.c : suites/test_suite_gcm.function suites/test_suite_gcm.aes256_en.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_gcm test_suite_gcm.aes256_en

test_suite_gcm.camellia.c : suites/test_suite_gcm.function suites/test_suite_gcm.camellia.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_gcm test_suite_gcm.camellia

test_suite_hmac_drbg.misc.c : suites/test_suite_hmac_drbg.function suites/test_suite_hmac_drbg.misc.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_hmac_drbg test_suite_hmac_drbg.misc

test_suite_hmac_drbg.no_reseed.c : suites/test_suite_hmac_drbg.function suites/test_suite_hmac_drbg.no_reseed.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_hmac_drbg test_suite_hmac_drbg.no_reseed

test_suite_hmac_drbg.nopr.c : suites/test_suite_hmac_drbg.function suites/test_suite_hmac_drbg.nopr.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_hmac_drbg test_suite_hmac_drbg.nopr

test_suite_hmac_drbg.pr.c : suites/test_suite_hmac_drbg.function suites/test_suite_hmac_drbg.pr.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites test_suite_hmac_drbg test_suite_hmac_drbg.pr

%.c : suites/%.function suites/%.data scripts/generate_code.pl suites/helpers.function suites/main_test.function
	echo   "  Generate	$@"
	scripts/generate_code.pl suites $* $*

test_suite_aes.ecb: test_suite_aes.ecb.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_aes.cbc: test_suite_aes.cbc.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_aes.cfb: test_suite_aes.cfb.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_aes.rest: test_suite_aes.rest.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_arc4: test_suite_arc4.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_asn1write: test_suite_asn1write.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_base64: test_suite_base64.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_blowfish: test_suite_blowfish.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_camellia: test_suite_camellia.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_ccm: test_suite_ccm.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_cipher.aes: test_suite_cipher.aes.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_cipher.arc4: test_suite_cipher.arc4.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_cipher.ccm: test_suite_cipher.ccm.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_cipher.gcm: test_suite_cipher.gcm.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_cipher.blowfish: test_suite_cipher.blowfish.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_cipher.camellia: test_suite_cipher.camellia.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_cipher.des: test_suite_cipher.des.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_cipher.null: test_suite_cipher.null.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_cipher.padding: test_suite_cipher.padding.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_ctr_drbg: test_suite_ctr_drbg.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_des: test_suite_des.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_dhm: test_suite_dhm.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_ecdh: test_suite_ecdh.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_ecdsa: test_suite_ecdsa.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_ecp: test_suite_ecp.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_entropy: test_suite_entropy.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_error: test_suite_error.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_gcm.aes128_de: test_suite_gcm.aes128_de.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_gcm.aes192_de: test_suite_gcm.aes192_de.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_gcm.aes256_de: test_suite_gcm.aes256_de.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_gcm.aes128_en: test_suite_gcm.aes128_en.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_gcm.aes192_en: test_suite_gcm.aes192_en.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_gcm.aes256_en: test_suite_gcm.aes256_en.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_gcm.camellia: test_suite_gcm.camellia.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_hmac_drbg.misc: test_suite_hmac_drbg.misc.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_hmac_drbg.no_reseed: test_suite_hmac_drbg.no_reseed.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_hmac_drbg.nopr: test_suite_hmac_drbg.nopr.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_hmac_drbg.pr: test_suite_hmac_drbg.pr.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_hmac_shax: test_suite_hmac_shax.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_md: test_suite_md.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_mdx: test_suite_mdx.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_mpi: test_suite_mpi.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_pbkdf2: test_suite_pbkdf2.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_pem: test_suite_pem.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_pkcs1_v21: test_suite_pkcs1_v21.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_pkcs5: test_suite_pkcs5.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_pkparse: test_suite_pkparse.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_pkwrite: test_suite_pkwrite.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_pk: test_suite_pk.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_rsa: test_suite_rsa.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_shax: test_suite_shax.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_x509parse: test_suite_x509parse.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_x509write: test_suite_x509write.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_xtea: test_suite_xtea.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_debug: test_suite_debug.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

test_suite_version: test_suite_version.c $(DEP)
	echo   "  CC    	$@.c"
	$(CC) $(CFLAGS) $(OFLAGS) $@.c	$(LDFLAGS) -o $@

clean:
ifndef WINDOWS
	rm -f $(APPS) *.c
endif
ifdef WINDOWS
	del /Q /F *.c *.exe
endif

check: $(APPS)
ifndef WINDOWS
	echo "Running checks (Success if all tests PASSED)"
	RETURN=0;																\
	for i in $(APPS);														\
	do																		\
		echo " - $${i}";													\
		RESULT=`$(CHECK_PRELOAD) ./$${i} | grep -v 'PASS$$' | grep -v -- '----' | grep -v '^$$'`;	\
		FAILED=`echo $$RESULT |grep FAILED`; 								\
		echo "   $$RESULT";													\
		if [ "$$FAILED" != "" ];											\
		then																\
			echo "**** Failed ***************";								\
			RETURN=1;														\
		fi; 																\
		echo "";															\
	done;																	\
	if [ "$$RETURN" -eq 1 ]; then exit 1; fi
endif
