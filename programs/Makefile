
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile with PKCS11: add "-lpkcs11-helper" to LDFLAGS

CFLAGS	?= -O2
WARNING_CFLAGS ?= -Wall -W -Wdeclaration-after-statement
WARNING_CXXFLAGS ?= -Wall -W
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../include -D_FILE_OFFSET_BITS=64
LOCAL_CXXFLAGS = $(WARNING_CXXFLAGS) -I../include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = -L../library 			\
		-lmbedtls$(SHARED_SUFFIX)	\
		-lmbedx509$(SHARED_SUFFIX)	\
		-lmbedcrypto$(SHARED_SUFFIX)

LOCAL_LDFLAGS += -L../crypto/library
LOCAL_CFLAGS += -I../crypto/include
LOCAL_CXXFLAGS += -I../crypto/include

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

APPS =	ssl/dtls_client$(EXEXT)		\
	ssl/dtls_server$(EXEXT)		\
	ssl/ssl_client1$(EXEXT)		\
	ssl/ssl_client2$(EXEXT)		\
	ssl/ssl_server$(EXEXT)		\
	ssl/ssl_server2$(EXEXT)		\
	ssl/ssl_fork_server$(EXEXT)	\
	ssl/mini_client$(EXEXT)		\
	ssl/ssl_mail_client$(EXEXT)	\
	test/ssl_cert_test$(EXEXT)	\
	test/benchmark$(EXEXT)		\
	test/selftest$(EXEXT)		\
	test/udp_proxy$(EXEXT)		\
	test/zeroize$(EXEXT)		\
	util/pem2der$(EXEXT)		\
	util/strerror$(EXEXT)		\
	x509/cert_app$(EXEXT)		\
	x509/crl_app$(EXEXT)		\
	x509/cert_req$(EXEXT)		\
	x509/cert_write$(EXEXT)		\
	x509/req_app$(EXEXT)

ifdef PTHREAD
APPS +=	ssl/ssl_pthread_server$(EXEXT)
endif

ifdef TEST_CPP
APPS += test/cpp_dummy_build$(EXEXT)
endif

.SILENT:

.PHONY: all clean list

all: $(APPS)

$(DEP):
	$(MAKE) -C ../library

ssl/dtls_client$(EXEXT): ssl/dtls_client.c $(DEP)
	echo "  CC    ssl/dtls_client.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/dtls_client.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/dtls_server$(EXEXT): ssl/dtls_server.c $(DEP)
	echo "  CC    ssl/dtls_server.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/dtls_server.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_client1$(EXEXT): ssl/ssl_client1.c $(DEP)
	echo "  CC    ssl/ssl_client1.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_client1.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_client2$(EXEXT): ssl/ssl_client2.c $(DEP)
	echo "  CC    ssl/ssl_client2.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_client2.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_server$(EXEXT): ssl/ssl_server.c $(DEP)
	echo "  CC    ssl/ssl_server.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_server.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_server2$(EXEXT): ssl/ssl_server2.c $(DEP)
	echo "  CC    ssl/ssl_server2.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_server2.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_fork_server$(EXEXT): ssl/ssl_fork_server.c $(DEP)
	echo "  CC    ssl/ssl_fork_server.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_fork_server.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_pthread_server$(EXEXT): ssl/ssl_pthread_server.c $(DEP)
	echo "  CC    ssl/ssl_pthread_server.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_pthread_server.c   $(LOCAL_LDFLAGS) -lpthread  $(LDFLAGS) -o $@

ssl/ssl_mail_client$(EXEXT): ssl/ssl_mail_client.c $(DEP)
	echo "  CC    ssl/ssl_mail_client.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_mail_client.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/mini_client$(EXEXT): ssl/mini_client.c $(DEP)
	echo "  CC    ssl/mini_client.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/mini_client.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/ssl_cert_test$(EXEXT): test/ssl_cert_test.c $(DEP)
	echo "  CC    test/ssl_cert_test.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/ssl_cert_test.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/benchmark$(EXEXT): test/benchmark.c $(DEP)
	echo "  CC    test/benchmark.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/benchmark.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/cpp_dummy_build$(EXEXT): test/cpp_dummy_build.cpp $(DEP)
	echo "  CXX   test/cpp_dummy_build.cpp"
	$(CXX) $(LOCAL_CXXFLAGS) $(CXXFLAGS) test/cpp_dummy_build.cpp   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/selftest$(EXEXT): test/selftest.c $(DEP)
	echo "  CC    test/selftest.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/selftest.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/udp_proxy$(EXEXT): test/udp_proxy.c $(DEP)
	echo "  CC    test/udp_proxy.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/udp_proxy.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/zeroize$(EXEXT): test/zeroize.c $(DEP)
	echo "  CC    test/zeroize.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/zeroize.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

util/pem2der$(EXEXT): util/pem2der.c $(DEP)
	echo "  CC    util/pem2der.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) util/pem2der.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

util/strerror$(EXEXT): util/strerror.c $(DEP)
	echo "  CC    util/strerror.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) util/strerror.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/cert_app$(EXEXT): x509/cert_app.c $(DEP)
	echo "  CC    x509/cert_app.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/cert_app.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/cert_write$(EXEXT): x509/cert_write.c $(DEP)
	echo "  CC    x509/cert_write.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/cert_write.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/crl_app$(EXEXT): x509/crl_app.c $(DEP)
	echo "  CC    x509/crl_app.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/crl_app.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/cert_req$(EXEXT): x509/cert_req.c $(DEP)
	echo "  CC    x509/cert_req.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/cert_req.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/req_app$(EXEXT): x509/req_app.c $(DEP)
	echo "  CC    x509/req_app.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/req_app.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

clean:
ifndef WINDOWS
	rm -f $(APPS)
else
	del /S /Q /F *.o *.exe
endif

list:
	echo $(APPS)
