
# Also see "include/polarssl/config.h"

CFLAGS	?= -O2
WARNING_CFLAGS ?=  -Wall -W -Wdeclaration-after-statement
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS =

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

# MicroBlaze specific options:
# CFLAGS += -mno-xl-soft-mul -mxl-barrel-shift

# To compile on Plan9:
# CFLAGS += -D_BSD_EXTENSION

# if were running on Windows build for Windows
ifdef WINDOWS
WINDOWS_BUILD=1
endif

# To compile as a shared library:
ifdef SHARED
# all code is position-indep with mingw, avoid warning about useless flag
ifndef WINDOWS_BUILD
LOCAL_CFLAGS += -fPIC -fpic
endif
endif

SOEXT=so.9

DLEXT=so
# OSX shared library extension:
# DLEXT=dylib

# Windows shared library extension:
ifdef WINDOWS_BUILD
DLEXT=dll
endif

OBJS=	aes.o		aesni.o		arc4.o			\
		asn1parse.o								\
		asn1write.o base64.o	bignum.o		\
		blowfish.o	camellia.o	ccm.o			\
		certs.o		cipher.o	cipher_wrap.o	\
		ctr_drbg.o	debug.o		des.o			\
		dhm.o		ecdh.o		ecdsa.o			\
		ecp.o		ecp_curves.o				\
		entropy.o	entropy_poll.o				\
		error.o		gcm.o		havege.o		\
		hmac_drbg.o								\
		md.o		md_wrap.o	md2.o			\
		md4.o		md5.o						\
		memory_buffer_alloc.o	net.o			\
		oid.o									\
		padlock.o	pbkdf2.o	pem.o			\
		pkcs5.o		pkcs11.o	pkcs12.o		\
		pk.o		pk_wrap.o	pkparse.o		\
		pkwrite.o	platform.o	ripemd160.o		\
		rsa.o		sha1.o		sha256.o		\
		sha512.o	ssl_cache.o	ssl_cli.o		\
		ssl_srv.o   ssl_ciphersuites.o			\
		ssl_tls.o	threading.o	timing.o		\
		version.o	version_features.o			\
		x509.o		x509_create.o				\
		x509_crl.o	x509_crt.o	x509_csr.o		\
		x509write_crt.o			x509write_csr.o	\
		xtea.o

.SILENT:

ifndef SHARED
all: static
else
all: shared static
endif

static: libpolarssl.a

shared: libpolarssl.$(DLEXT)

libpolarssl.a: libmbedtls.a
	echo "  LN    $@ -> $?"
ifndef WINDOWS
	ln -sf $? $@
else
	copy /y /b $? $@
endif

libmbedtls.a: $(OBJS)
	echo "  AR    $@"
	$(AR) rc $@ $(OBJS)
	echo "  RL    $@"
	$(AR) s $@

libpolarssl.$(DLEXT): libmbedtls.$(DLEXT)
	echo "  LN    $@ -> $?"
ifndef WINDOWS
	ln -sf $? $@
else
	copy /y /b $? $@
endif
ifdef WINDOWS_BUILD
ifndef WINDOWS
	ln -sf $?.a $@.a
else
	copy /y /b $?.a $@.a
endif
endif

libmbedtls.$(SOEXT): $(OBJS)
	echo "  LD    $@"
	$(CC) -shared -Wl,-soname,$@ $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS)

libmbedtls.so: libmbedtls.$(SOEXT)
	echo "  LN    $@ -> libmbedtls.$(SOEXT)"
	ln -sf libmbedtls.$(SOEXT) $@

libmbedtls.dylib: $(OBJS)
	echo "  LD    $@"
	$(CC) -dynamiclib $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS)

libmbedtls.dll: $(OBJS)
	echo "  LD    $@"
	$(CC) -shared -Wl,-soname,$@ -Wl,--out-implib,$@.a -o $@ $(OBJS) -lws2_32 -lwinmm -lgdi32 $(LOCAL_LDFLAGS) $(LDFLAGS)

.c.o:
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -c $<

clean:
ifndef WINDOWS
	rm -f *.o libpolarssl.* libmbedtls.*
endif
ifdef WINDOWS
	del /Q /F *.o libpolarssl.* libmbedtls.*
endif
