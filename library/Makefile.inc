SOEXT_TLS=so.17
SOEXT_X509=so.4
SOEXT_CRYPTO=so.11

# Set AR_DASH= (empty string) to use an ar implementation that does not accept
# the - prefix for command line options (e.g. llvm-ar)
AR_DASH ?= -

ARFLAGS = $(AR_DASH)src
ifdef APPLE_BUILD
ifneq ($(APPLE_BUILD),0)
ARFLAGS = $(AR_DASH)Src
RLFLAGS = -no_warning_for_no_symbols -c
RL ?= ranlib
endif
endif

OBJS_CRYPTO= \
	     aes.o \
	     aesni.o \
	     aria.o \
	     asn1parse.o \
	     asn1write.o \
	     base64.o \
	     bignum.o \
	     camellia.o \
	     ccm.o \
	     chacha20.o \
	     chachapoly.o \
	     cipher.o \
	     cipher_wrap.o \
	     cmac.o \
	     constant_time.o \
	     ctr_drbg.o \
	     des.o \
	     dhm.o \
	     ecdh.o \
	     ecdsa.o \
	     ecjpake.o \
	     ecp.o \
	     ecp_curves.o \
	     entropy.o \
	     entropy_poll.o \
	     error.o \
	     gcm.o \
	     hkdf.o \
	     hmac_drbg.o \
	     md.o \
	     md5.o \
	     memory_buffer_alloc.o \
	     mps_reader.o \
	     mps_trace.o \
	     nist_kw.o \
	     oid.o \
	     padlock.o \
	     pem.o \
	     pk.o \
	     pk_wrap.o \
	     pkcs12.o \
	     pkcs5.o \
	     pkparse.o \
	     pkwrite.o \
	     platform.o \
	     platform_util.o \
	     poly1305.o \
	     psa_crypto.o \
	     psa_crypto_aead.o \
	     psa_crypto_cipher.o \
	     psa_crypto_client.o \
	     psa_crypto_driver_wrappers.o \
	     psa_crypto_ecp.o \
	     psa_crypto_hash.o \
	     psa_crypto_mac.o \
	     psa_crypto_rsa.o \
	     psa_crypto_se.o \
	     psa_crypto_slot_management.o \
	     psa_crypto_storage.o \
	     psa_its_file.o \
	     ripemd160.o \
	     rsa.o \
	     rsa_alt_helpers.o \
	     sha1.o \
	     sha256.o \
	     sha512.o \
	     ssl_debug_helpers_generated.o \
	     threading.o \
	     timing.o \
	     version.o \
	     version_features.o \
	     # This line is intentionally left blank

OBJS_CRYPTO := $(patsubst %,library/%,$(OBJS_CRYPTO))

include 3rdparty/Makefile.inc
LOCAL_CFLAGS+=$(THIRDPARTY_INCLUDES)
OBJS_CRYPTO+=$(THIRDPARTY_CRYPTO_OBJECTS)

OBJS_X509= \
	   x509.o \
	   x509_create.o \
	   x509_crl.o \
	   x509_crt.o \
	   x509_csr.o \
	   x509write_crt.o \
	   x509write_csr.o \
	   # This line is intentionally left blank

OBJS_X509 := $(patsubst %,library/%,$(OBJS_X509))

OBJS_TLS= \
	  debug.o \
	  net_sockets.o \
	  ssl_cache.o \
	  ssl_ciphersuites.o \
	  ssl_cli.o \
	  ssl_cookie.o \
	  ssl_msg.o \
	  ssl_srv.o \
	  ssl_ticket.o \
	  ssl_tls.o \
	  ssl_tls13_keys.o \
	  ssl_tls13_client.o \
	  ssl_tls13_server.o \
	  ssl_tls13_generic.o \
	  # This line is intentionally left blank

OBJS_TLS := $(patsubst %,library/%,$(OBJS_TLS))

.PHONY: library/all library/static library/shared library/clean

LOCAL = library/% $(THIRDPARTY_CRYPTO_OBJECTS)

# Include ../include for public headers and . for private headers.
# Note that . needs to be included explicitly for the sake of library
# files that are not in the /library directory (which currently means
# under /3rdparty).
$(LOCAL): LOCAL_CFLAGS += $(WARNING_CFLAGS) -I. -I../include -D_FILE_OFFSET_BITS=64

# To compile as a shared library:
ifdef SHARED
# all code is position-indep with mingw, avoid warning about useless flag
ifndef WINDOWS_BUILD
$(LOCAL): LOCAL_CFLAGS += -fPIC -fpic
endif
endif

$(LOCAL): BUILD_DIR = library

ifndef SHARED
library/all: library/static
else
library/all: library/shared library/static
endif

library/static: library/libmbedcrypto.a library/libmbedx509.a library/libmbedtls.a

library/shared: library/libmbedcrypto.$(DLEXT) library/libmbedx509.$(DLEXT) library/libmbedtls.$(DLEXT)

# Windows builds under Mingw can fail if make tries to create archives in the same
# directory at the same time - see https://bugs.launchpad.net/gcc-arm-embedded/+bug/1848002.
# This forces builds of the .a files to be serialised.
ifdef WINDOWS
library/libmbedtls.a: | library/libmbedx509.a
library/libmbedx509.a: | library/libmbedcrypto.a
endif

# tls
library/libmbedtls.a: $(OBJS_TLS)
	echo "  AR    $@"
	$(AR) $(ARFLAGS) $@ $(OBJS_TLS)
ifdef APPLE_BUILD
ifneq ($(APPLE_BUILD),0)
	echo "  RL    $@"
	$(RL) $(RLFLAGS) $@
endif
endif

library/libmbedtls.$(SOEXT_TLS): $(OBJS_TLS) library/libmbedx509.so
	echo "  LD    $@"
	cd $(BUILD_DIR) && $(CC) -shared -Wl,-soname,$(@F) -o $(abspath $@) $(abspath $(OBJS_TLS)) -L. -lmbedx509 -lmbedcrypto $(LOCAL_LDFLAGS) $(LDFLAGS)

library/libmbedtls.so: library/libmbedtls.$(SOEXT_TLS)
	echo "  LN    $@ -> $(<F)"
	ln -sf $(<F) $@

library/libmbedtls.dylib: $(OBJS_TLS) library/libmbedx509.dylib
	echo "  LD    $@"
	cd $(BUILD_DIR) && $(CC) -dynamiclib -o $(abspath $@) $(abspath $(OBJS_TLS)) -L. -lmbedx509 -lmbedcrypto $(LOCAL_LDFLAGS) $(LDFLAGS)

library/libmbedtls.dll: $(OBJS_TLS) library/libmbedx509.dll
	echo "  LD    $@"
	cd $(BUILD_DIR) && $(CC) -shared -Wl,-soname,$(@F) -Wl,--out-implib,$(abspath $@).a -o $(abspath $@) $(abspath $(OBJS_TLS)) -lwinmm -lgdi32 -L. -lmbedx509 -lmbedcrypto -static-libgcc $(LOCAL_LDFLAGS) $(LDFLAGS)

# x509
library/libmbedx509.a: $(OBJS_X509)
	echo "  AR    $@"
	$(AR) $(ARFLAGS) $@ $(OBJS_X509)
ifdef APPLE_BUILD
ifneq ($(APPLE_BUILD),0)
	echo "  RL    $@"
	$(RL) $(RLFLAGS) $@
endif
endif

library/libmbedx509.$(SOEXT_X509): $(OBJS_X509) library/libmbedcrypto.so
	echo "  LD    $@"
	cd $(BUILD_DIR) && $(CC) -shared -Wl,-soname,$(@F) -o $(abspath $@) $(abspath $(OBJS_X509)) -L. -lmbedcrypto $(LOCAL_LDFLAGS) $(LDFLAGS)

library/libmbedx509.so: library/libmbedx509.$(SOEXT_X509)
	echo "  LN    $@ -> $(<F)"
	ln -sf $(<F) $@

library/libmbedx509.dylib: $(OBJS_X509) library/libmbedcrypto.dylib
	echo "  LD    $@"
	cd $(BUILD_DIR) && $(CC) -dynamiclib -o $(abspath $@) $(abspath $(OBJS_X509)) -L. -lmbedcrypto  $(LOCAL_LDFLAGS) $(LDFLAGS)

library/libmbedx509.dll: $(OBJS_X509) library/libmbedcrypto.dll
	echo "  LD    $@"
	cd $(BUILD_DIR) && $(CC) -shared -Wl,-soname,$(@F) -Wl,--out-implib,$(abspath $@).a -o $(abspath $@) $(abspath $(OBJS_X509)) -lwinmm -lgdi32 -L. -lmbedcrypto -static-libgcc $(LOCAL_LDFLAGS) $(LDFLAGS)

# crypto
library/libmbedcrypto.a: $(OBJS_CRYPTO)
	echo "  AR    $@"
	$(AR) $(ARFLAGS) $@ $(OBJS_CRYPTO)
ifdef APPLE_BUILD
ifneq ($(APPLE_BUILD),0)
	echo "  RL    $@"
	$(RL) $(RLFLAGS) $@
endif
endif

library/libmbedcrypto.$(SOEXT_CRYPTO): $(OBJS_CRYPTO)
	echo "  LD    $@"
	cd $(BUILD_DIR) && $(CC) -shared -Wl,-soname,$(@F) -o $(abspath $@) $(abspath $(OBJS_CRYPTO)) $(LOCAL_LDFLAGS) $(LDFLAGS)

library/libmbedcrypto.so: library/libmbedcrypto.$(SOEXT_CRYPTO)
	echo "  LN    $@ -> $(<F)"
	ln -sf $(<F) $@

library/libmbedcrypto.dylib: $(OBJS_CRYPTO)
	echo "  LD    $@"
	cd $(BUILD_DIR) && $(CC) -dynamiclib -o $(abspath $@) $(abspath $(OBJS_CRYPTO)) $(LOCAL_LDFLAGS) $(LDFLAGS)

library/libmbedcrypto.dll: $(OBJS_CRYPTO)
	echo "  LD    $@"
	cd $(BUILD_DIR) && $(CC) -shared -Wl,-soname,$(@F) -Wl,--out-implib,$(abspath $@).a -o $(abspath $@) $(abspath $(OBJS_CRYPTO)) -lwinmm -lgdi32 -static-libgcc $(LOCAL_LDFLAGS) $(LDFLAGS)

.PHONY: library/generated_files
GENERATED_FILES = \
	error.c version_features.c \
	ssl_debug_helpers_generated.c \
        psa_crypto_driver_wrappers.c
GENERATED_FILES := $(patsubst %,library/%,$(GENERATED_FILES))

library/generated_files: $(GENERATED_FILES)

library/error.c: scripts/generate_errors.pl
library/error.c: scripts/data_files/error.fmt
library/error.c: $(filter-out library/%config%,$(wildcard include/mbedtls/*.h))
library/error.c:
	echo "  Gen   $@"
	$(PERL) scripts/generate_errors.pl

library/ssl_debug_helpers_generated.c: scripts/generate_ssl_debug_helpers.py
library/ssl_debug_helpers_generated.c: $(filter-out library/%config%,$(wildcard include/mbedtls/*.h))
library/ssl_debug_helpers_generated.c:
	echo "  Gen   $@"
	$(PYTHON) scripts/generate_ssl_debug_helpers.py --mbedtls-root . library

library/version_features.c: scripts/generate_features.pl
library/version_features.c: scripts/data_files/version_features.fmt
## The generated file only depends on the options that are present in mbedtls_config.h,
## not on which options are set. To avoid regenerating this file all the time
## when switching between configurations, don't declare mbedtls_config.h as a
## dependency. Remove this file from your working tree if you've just added or
## removed an option in mbedtls_config.h.
#library/version_features.c: include/mbedtls/mbedtls_config.h
library/version_features.c:
	echo "  Gen   $@"
	$(PERL) scripts/generate_features.pl

library/psa_crypto_driver_wrappers.c: scripts/generate_driver_wrappers.py
library/psa_crypto_driver_wrappers.c: scripts/data_files/driver_templates/psa_crypto_driver_wrappers.c.jinja
library/psa_crypto_driver_wrappers.c:
	echo "  Gen   $@"
	$(PYTHON) scripts/generate_driver_wrappers.py

library/clean:
ifndef WINDOWS
	rm -f library/*.o library/libmbed*
	rm -f $(THIRDPARTY_CRYPTO_OBJECTS)
else
	for %%f in (library\*.o library\libmbed* $(subst /,\,$(THIRDPARTY_CRYPTO_OBJECTS))) do if exist %%f del /Q /F %%f
endif

library/neat: library/clean
ifndef WINDOWS
	rm -f $(GENERATED_FILES)
else
	for %%f in ($(subst /,\,$(GENERATED_FILES))) do if exist %%f del /Q /F %%f
endif
