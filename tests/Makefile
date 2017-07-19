
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

# Enable definition of various functions used throughout the testsuite
# (gethostname, strdup, fileno...) even when compiling with -std=c99. Harmless
# on non-POSIX platforms.
LOCAL_CFLAGS += -D_POSIX_C_SOURCE=200809L

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
PYTHON ?= python
else
DLEXT ?= so
EXEXT=
SHARED_SUFFIX=
# python2 for POSIX since FreeBSD has only python2 as default.
PYTHON ?= python2
endif

# Zlib shared library extensions:
ifdef ZLIB
LOCAL_LDFLAGS += -lz
endif

<<<<<<< HEAD
# A test application is built for each suites/test_suite_*.data file.
# Application name is same as .data file's base name and can be
# constructed by stripping path 'suites/' and extension .data.
APPS = $(basename $(subst suites/,,$(wildcard suites/test_suite_*.data)))

# Construct executable name by adding OS specific suffix $(EXEXT).
BINARIES := $(addsuffix $(EXEXT),$(APPS))
=======
APPS =	test_suite_aes.ecb$(EXEXT)	test_suite_aes.cbc$(EXEXT)	\
	test_suite_aes.cfb$(EXEXT)	test_suite_aes.ofb$(EXEXT)	\
	test_suite_aes.xts$(EXEXT)					\
	test_suite_aes.rest$(EXEXT)	test_suite_arc4$(EXEXT)		\
	test_suite_aria$(EXEXT)		test_suite_asn1write$(EXEXT)	\
	test_suite_base64$(EXEXT)	test_suite_blowfish$(EXEXT)	\
	test_suite_camellia$(EXEXT)	test_suite_ccm$(EXEXT)		\
	test_suite_chacha20$(EXEXT)	test_suite_chachapoly$(EXEXT)	\
	test_suite_cmac$(EXEXT)						\
	test_suite_cipher.chachapoly$(EXEXT)				\
	test_suite_cipher.aes$(EXEXT)					\
	test_suite_cipher.arc4$(EXEXT)	test_suite_cipher.ccm$(EXEXT)	\
	test_suite_cipher.chacha20$(EXEXT)				\
	test_suite_cipher.gcm$(EXEXT)					\
	test_suite_cipher.blowfish$(EXEXT)				\
	test_suite_cipher.camellia$(EXEXT)				\
	test_suite_cipher.des$(EXEXT)	test_suite_cipher.null$(EXEXT)	\
	test_suite_cipher.padding$(EXEXT)				\
	test_suite_ctr_drbg$(EXEXT)	test_suite_debug$(EXEXT)	\
	test_suite_des$(EXEXT)		test_suite_dhm$(EXEXT)		\
	test_suite_ecdh$(EXEXT)		test_suite_ecdsa$(EXEXT)	\
	test_suite_ecjpake$(EXEXT)	test_suite_ecp$(EXEXT)		\
	test_suite_error$(EXEXT)	test_suite_entropy$(EXEXT)	\
	test_suite_gcm.aes128_de$(EXEXT)				\
	test_suite_gcm.aes192_de$(EXEXT)				\
	test_suite_gcm.aes256_de$(EXEXT)				\
	test_suite_gcm.aes128_en$(EXEXT)				\
	test_suite_gcm.aes192_en$(EXEXT)				\
	test_suite_gcm.aes256_en$(EXEXT)				\
	test_suite_gcm.camellia$(EXEXT)					\
	test_suite_hkdf$(EXEXT)						\
	test_suite_hmac_drbg.misc$(EXEXT)				\
	test_suite_hmac_drbg.no_reseed$(EXEXT)				\
	test_suite_hmac_drbg.nopr$(EXEXT)				\
	test_suite_hmac_drbg.pr$(EXEXT)					\
	test_suite_md$(EXEXT)		test_suite_mdx$(EXEXT)		\
	test_suite_memory_buffer_alloc$(EXEXT)				\
	test_suite_mpi$(EXEXT)						\
	test_suite_nist_kw$(EXEXT)						\
	test_suite_pem$(EXEXT)			test_suite_pkcs1_v15$(EXEXT)	\
	test_suite_pkcs1_v21$(EXEXT)	test_suite_pkcs5$(EXEXT)	\
	test_suite_pkparse$(EXEXT)	test_suite_pkwrite$(EXEXT)	\
	test_suite_pk$(EXEXT)						\
	test_suite_poly1305$(EXEXT)					\
	test_suite_rsa$(EXEXT)		test_suite_shax$(EXEXT)		\
	test_suite_ssl$(EXEXT)		test_suite_timing$(EXEXT)			\
	test_suite_x509parse$(EXEXT)	test_suite_x509write$(EXEXT)	\
	test_suite_xtea$(EXEXT)		test_suite_version$(EXEXT)	\
    test_suite_fs_abstraction$(EXEXT)
>>>>>>> FS abstraction

.SILENT:

.PHONY: all check test clean

all: $(BINARIES)

$(DEP):
	$(MAKE) -C ../library

C_FILES := $(addsuffix .c,$(APPS))

# Wildcard target for test code generation:
# A .c file is generated for each .data file in the suites/ directory. Each .c
# file depends on a .data and .function file from suites/ directory. Following
# nameing convention is followed:
#
#     C file        |        Depends on
#-----------------------------------------------------------------------------
#  foo.c            | suites/foo.function suites/foo.data
#  foo.bar.c        | suites/foo.function suites/foo.bar.data
#
# Note above that .c and .data files have same base name.
# However, corresponding .function file's base name is the word before first
# dot in .c file's base name.
#
.SECONDEXPANSION:
%.c: suites/$$(firstword $$(subst ., ,$$*)).function suites/%.data scripts/generate_test_code.py suites/helpers.function suites/main_test.function suites/host_test.function
	echo "  Gen   $@"
	$(PYTHON) scripts/generate_test_code.py -f suites/$(firstword $(subst ., ,$*)).function \
		-d suites/$*.data \
		-t suites/main_test.function \
		-p suites/host_test.function \
		-s suites  \
		--helpers-file suites/helpers.function \
		-o .


$(BINARIES): %$(EXEXT): %.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@


clean:
ifndef WINDOWS
	rm -rf $(APPS) *.c *.datax TESTS
else
	del /Q /F *.c *.exe *.datax
ifneq ($(wildcard TESTS/.*),)
	rmdir /Q /S TESTS
endif
endif

check: $(BINARIES)
	perl scripts/run-test-suites.pl

test: check

# Create separate targets for generating embedded tests.
EMBEDDED_TESTS := $(addprefix embedded_,$(APPS))

# Generate test code for target.

.SECONDEXPANSION:
$(EMBEDDED_TESTS): embedded_%: suites/$$(firstword $$(subst ., ,$$*)).function suites/%.data scripts/generate_test_code.py suites/helpers.function suites/main_test.function suites/target_test.function
	echo "  Gen  ./TESTS/mbedtls/$*/$*.c"
	$(PYTHON) scripts/generate_test_code.py -f suites/$(firstword $(subst ., ,$*)).function \
		-d suites/$*.data \
		-t suites/main_test.function \
		-p suites/target_test.function \
		-s suites  \
		--helpers-file suites/helpers.function \
		-o ./TESTS/mbedtls/$*

generate-target-tests: $(EMBEDDED_TESTS)

