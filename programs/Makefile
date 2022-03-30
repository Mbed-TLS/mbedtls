# If we are the top level Makefile, call the one in the root dir instead
ifeq ($(words $(MAKEFILE_LIST)),1)
.SILENT:
.PHONY: all
all:
	$(MAKE) -C .. $(patsubst %,programs/%,$(or $(MAKECMDGOALS),all))

$(filter-out all,$(MAKECMDGOALS)): all
else
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS

WARNING_CXXFLAGS ?= -Wall -Wextra -Wformat=2 -Wno-format-nonliteral

MBEDTLS_TEST_PATH:=tests/src
MBEDTLS_TEST_OBJS:=$(patsubst %.c,%.o,$(wildcard ${MBEDTLS_TEST_PATH}/*.c ${MBEDTLS_TEST_PATH}/drivers/*.c))

programs/%: LOCAL_CFLAGS += $(WARNING_CFLAGS) -I../tests/include -I../include -D_FILE_OFFSET_BITS=64
programs/%: LOCAL_CXXFLAGS += $(WARNING_CXXFLAGS) -I../include -I../tests/include -D_FILE_OFFSET_BITS=64
programs/%: LOCAL_LDFLAGS := $(LOCAL_LDFLAGS)	\
		-L../library 			\
		-lmbedtls$(SHARED_SUFFIX)	\
		-lmbedx509$(SHARED_SUFFIX)	\
		-lmbedcrypto$(SHARED_SUFFIX)

ifeq ($(shell uname -s),Linux)
DLOPEN_LDFLAGS ?= -ldl
else
DLOPEN_LDFLAGS ?=
endif

programs/%: LOCAL_CFLAGS+=$(THIRDPARTY_INCLUDES)

DEP=${MBEDLIBS} ${MBEDTLS_TEST_OBJS}

# Only build the dlopen test in shared library builds, and not when building
# for Windows.
ifdef BUILD_DLOPEN
# Don't override the value
else ifdef WINDOWS_BUILD
BUILD_DLOPEN =
else ifdef SHARED
BUILD_DLOPEN = y
else
BUILD_DLOPEN =
endif

## The following assignment is the list of base names of applications that
## will be built on Windows. Extra Linux/Unix/POSIX-only applications can
## be declared by appending with `APPS += ...` afterwards.
## See the get_app_list function in scripts/generate_visualc_files.pl and
## make sure to check that it still works if you tweak the format here.
APPS = \
	aes/crypt_and_hash \
	cipher/cipher_aead_demo \
	hash/generic_sum \
	hash/hello \
	hash/md_hmac_demo \
	pkey/dh_client \
	pkey/dh_genprime \
	pkey/dh_server \
	pkey/ecdh_curve25519 \
	pkey/ecdsa \
	pkey/gen_key \
	pkey/key_app \
	pkey/key_app_writer \
	pkey/mpi_demo \
	pkey/pk_decrypt \
	pkey/pk_encrypt \
	pkey/pk_sign \
	pkey/pk_verify \
	pkey/rsa_decrypt \
	pkey/rsa_encrypt \
	pkey/rsa_genkey \
	pkey/rsa_sign \
	pkey/rsa_sign_pss \
	pkey/rsa_verify \
	pkey/rsa_verify_pss \
	psa/aead_demo \
	psa/crypto_examples \
	psa/hmac_demo \
	psa/key_ladder_demo \
	psa/psa_constant_names \
	random/gen_entropy \
	random/gen_random_ctr_drbg \
	ssl/dtls_client \
	ssl/dtls_server \
	ssl/mini_client \
	ssl/ssl_client1 \
	ssl/ssl_client2 \
	ssl/ssl_context_info \
	ssl/ssl_fork_server \
	ssl/ssl_mail_client \
	ssl/ssl_server \
	ssl/ssl_server2 \
	test/benchmark \
	test/query_compile_time_config \
	test/selftest \
	test/udp_proxy \
	test/zeroize \
	util/pem2der \
	util/strerror \
	x509/cert_app \
	x509/cert_req \
	x509/cert_write \
	x509/crl_app \
	x509/load_roots \
	x509/req_app \
# End of APPS

ifdef PTHREAD
APPS +=	ssl/ssl_pthread_server
endif

ifdef BUILD_DLOPEN
APPS +=	test/dlopen
endif

ifdef TEST_CPP
APPS += test/cpp_dummy_build
endif

APPS := $(addprefix programs/,$(APPS))

EXES = $(patsubst %,%$(EXEXT),$(APPS))

.SILENT:

.PHONY: programs/all programs/clean programs/list programs/fuzz

programs/%: BUILD_DIR = programs

programs/all: $(EXES)
ifndef WINDOWS
# APPS doesn't include the fuzzing programs, which aren't "normal"
# sample or test programs, and don't build with MSVC which is
# warning about fopen
programs/all: programs/fuzz
endif

programs/fuzz: $(MBEDTLS_TEST_OBJS)
	$(MAKE) -C programs/fuzz THIRDPARTY_INCLUDES=$(THIRDPARTY_INCLUDES)

.PHONY: programs/generated_files
GENERATED_PROGRAM_FILES = programs/psa/psa_constant_names_generated.c programs/test/query_config.c
programs/generated_files: $(GENERATED_PROGRAM_FILES)

programs/psa/psa_constant_names_generated.c: scripts/generate_psa_constants.py
programs/psa/psa_constant_names_generated.c: include/psa/crypto_values.h
programs/psa/psa_constant_names_generated.c: include/psa/crypto_extra.h
programs/psa/psa_constant_names_generated.c: tests/suites/test_suite_psa_crypto_metadata.data
programs/psa/psa_constant_names_generated.c:
	echo "  Gen   $@"
	$(PYTHON) scripts/generate_psa_constants.py

programs/test/query_config.c: scripts/generate_query_config.pl
## The generated file only depends on the options that are present in mbedtls_config.h,
## not on which options are set. To avoid regenerating this file all the time
## when switching between configurations, don't declare mbedtls_config.h as a
## dependency. Remove this file from your working tree if you've just added or
## removed an option in mbedtls_config.h.
#programs/test/query_config.c: include/mbedtls/mbedtls_config.h
programs/test/query_config.c: scripts/data_files/query_config.fmt
programs/test/query_config.c:
	echo "  Gen   $@"
	$(PERL) scripts/generate_query_config.pl

.cpp.o:
	echo "  CXX   $<"
	cd $(BUILD_DIR) && $(CXX) $(LOCAL_CXXFLAGS) $(CXXFLAGS) -o $(abspath $@) -c $(abspath $<)

$(EXES): %$(EXEXT): %.o $(MBEDTLS_TEST_OBJS) $(MBEDLIBS)
	echo "  LD    $@"
	cd $(BUILD_DIR) && $(CC) $(abspath $(filter %.o,$^)) $(LOCAL_LDFLAGS) $(LDFLAGS) -o $(abspath $@)

programs/psa/psa_constant_names.o: programs/psa/psa_constant_names_generated.c

SSL_TEST_OBJECTS = programs/test/query_config.o programs/ssl/ssl_test_lib.o
SSL_TEST_DEPS = programs/test/query_config.h \
		programs/ssl/ssl_test_lib.h \
		programs/ssl/ssl_test_common_source.c

programs/ssl/ssl_test_lib.o: programs/ssl/ssl_test_lib.h

programs/ssl/ssl_client2.o ssl/ssl_server2.o: $(SSL_TEST_DEPS)
programs/ssl/ssl_client2$(EXEXT) programs/ssl/ssl_server2$(EXEXT): $(SSL_TEST_OBJECTS)

programs/ssl/ssl_context_info.o: programs/test/query_config.h
programs/ssl/ssl_context_info$(EXEXT): programs/test/query_config.o

programs/test/cpp_dummy_build.cpp: programs/test/generate_cpp_dummy_build.sh
	echo "  Gen   test/cpp_dummy_build.cpp"
	programs/test/generate_cpp_dummy_build.sh

# Do not link any test objects (that would bring in a static dependency on
# libmbedcrypto at least). Do not link with libmbed* (that would defeat the
# purpose of testing dynamic loading).
programs/test/dlopen$(EXEXT): LOCAL_LDFLAGS =
programs/test/dlopen$(EXEXT): LDFLAGS += $(DLOPEN_LDFLAGS)

programs/test/query_config.o: programs/test/query_config.h

programs/test/query_compile_time_config.o: programs/test/query_config.h
programs/test/query_compile_time_config$(EXEXT): programs/test/query_config.o

CLEANOBJS := $(patsubst %,%*.o,$(sort $(dir $(APPS))))
programs/clean:
ifndef WINDOWS
	rm -f $(EXES) $(CLEANOBJS)
	-rm -f programs/ssl/ssl_pthread_server$(EXEXT)
	-rm -f programs/test/cpp_dummy_build.cpp programs/test/cpp_dummy_build$(EXEXT)
	-rm -f programs/test/dlopen$(EXEXT)
else
	for %%f in ($(subst /,\,$(CLEANOBJS) $(patsubst %o,%exe,$(CLEANOBJS)))) do del /Q /F %%f
	if exist programs\test\cpp_dummy_build.cpp del /Q /F programs\test\cpp_dummy_build.cpp
endif
	$(MAKE) -C programs/fuzz clean

programs/neat: programs/clean
ifndef WINDOWS
	rm -f $(GENERATED_PROGRAM_FILES)
else
	for %%f in ($(subst /,\,$(GENERATED_PROGRAM_FILES))) do if exist %%f del /Q /F %%f
endif

programs/list:
	echo $(EXES)
endif
