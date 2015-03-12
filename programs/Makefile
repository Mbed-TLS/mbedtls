
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile with PKCS11: add "-lpkcs11-helper" to LDFLAGS

CFLAGS	?= -O2
WARNING_CFLAGS ?= -Wall -W -Wdeclaration-after-statement
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = -L../library -lmbedtls$(SHARED_SUFFIX)

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

#
# if we running on Windows build
# for Windows
#
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
endif

# Zlib shared library extensions:
ifdef ZLIB
LOCAL_LDFLAGS += -lz
endif

APPS =	aes/aescrypt2$(EXEXT)		aes/crypt_and_hash$(EXEXT)	\
	hash/hello$(EXEXT)		hash/generic_sum$(EXEXT)	\
	hash/md5sum$(EXEXT)		hash/sha1sum$(EXEXT)		\
	hash/sha2sum$(EXEXT)		pkey/dh_client$(EXEXT)		\
	pkey/dh_genprime$(EXEXT)	pkey/dh_server$(EXEXT)		\
	pkey/gen_key$(EXEXT)						\
	pkey/key_app$(EXEXT)		pkey/key_app_writer$(EXEXT)	\
	pkey/mpi_demo$(EXEXT)		pkey/pk_decrypt$(EXEXT)		\
	pkey/pk_encrypt$(EXEXT)		pkey/pk_sign$(EXEXT)		\
	pkey/pk_verify$(EXEXT)		pkey/rsa_genkey$(EXEXT)		\
	pkey/rsa_decrypt$(EXEXT)	pkey/rsa_encrypt$(EXEXT)	\
	pkey/rsa_sign$(EXEXT)		pkey/rsa_verify$(EXEXT)		\
	pkey/rsa_sign_pss$(EXEXT)	pkey/rsa_verify_pss$(EXEXT)	\
	ssl/ssl_client1$(EXEXT)		ssl/ssl_client2$(EXEXT)		\
	ssl/ssl_server$(EXEXT)		ssl/ssl_server2$(EXEXT)		\
	ssl/ssl_fork_server$(EXEXT)	ssl/mini_client$(EXEXT)		\
	ssl/ssl_mail_client$(EXEXT)	random/gen_entropy$(EXEXT)	\
	random/gen_random_havege$(EXEXT)				\
	random/gen_random_ctr_drbg$(EXEXT)				\
	test/ssl_cert_test$(EXEXT)	test/benchmark$(EXEXT)		\
	test/selftest$(EXEXT)		test/ssl_test$(EXEXT)		\
	util/pem2der$(EXEXT)		util/strerror$(EXEXT)		\
	x509/cert_app$(EXEXT)		x509/crl_app$(EXEXT)		\
	x509/cert_req$(EXEXT)

ifdef OPENSSL
APPS +=	test/o_p_test
endif

ifdef PTHREAD
APPS +=	ssl/ssl_pthread_server
endif

.SILENT:

all: $(APPS)

aes/aescrypt2$(EXEXT): aes/aescrypt2.c ../library/libmbedtls.a
	echo   "  CC    aes/aescrypt2.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) aes/aescrypt2.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

aes/crypt_and_hash$(EXEXT): aes/crypt_and_hash.c ../library/libmbedtls.a
	echo   "  CC    aes/crypt_and_hash.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) aes/crypt_and_hash.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

hash/hello$(EXEXT): hash/hello.c ../library/libmbedtls.a
	echo   "  CC    hash/hello.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) hash/hello.c       $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

hash/generic_sum$(EXEXT): hash/generic_sum.c ../library/libmbedtls.a
	echo   "  CC    hash/generic_sum.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) hash/generic_sum.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

hash/md5sum$(EXEXT): hash/md5sum.c ../library/libmbedtls.a
	echo   "  CC    hash/md5sum.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) hash/md5sum.c      $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

hash/sha1sum$(EXEXT): hash/sha1sum.c ../library/libmbedtls.a
	echo   "  CC    hash/sha1sum.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) hash/sha1sum.c     $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

hash/sha2sum$(EXEXT): hash/sha2sum.c ../library/libmbedtls.a
	echo   "  CC    hash/sha2sum.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) hash/sha2sum.c     $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/dh_client$(EXEXT): pkey/dh_client.c ../library/libmbedtls.a
	echo   "  CC    pkey/dh_client.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/dh_client.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/dh_genprime$(EXEXT): pkey/dh_genprime.c ../library/libmbedtls.a
	echo   "  CC    pkey/dh_genprime.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/dh_genprime.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/dh_server$(EXEXT): pkey/dh_server.c ../library/libmbedtls.a
	echo   "  CC    pkey/dh_server.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/dh_server.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/ecdsa$(EXEXT): pkey/ecdsa.c ../library/libmbedtls.a
	echo   "  CC    pkey/ecdsa.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/ecdsa.c       $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/gen_key$(EXEXT): pkey/gen_key.c ../library/libmbedtls.a
	echo   "  CC    pkey/gen_key.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/gen_key.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/key_app$(EXEXT): pkey/key_app.c ../library/libmbedtls.a
	echo   "  CC    pkey/key_app.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/key_app.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/key_app_writer$(EXEXT): pkey/key_app_writer.c ../library/libmbedtls.a
	echo   "  CC    pkey/key_app_writer.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/key_app_writer.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/mpi_demo$(EXEXT): pkey/mpi_demo.c ../library/libmbedtls.a
	echo   "  CC    pkey/mpi_demo.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/mpi_demo.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/pk_decrypt$(EXEXT): pkey/pk_decrypt.c ../library/libmbedtls.a
	echo   "  CC    pkey/pk_decrypt.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/pk_decrypt.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/pk_encrypt$(EXEXT): pkey/pk_encrypt.c ../library/libmbedtls.a
	echo   "  CC    pkey/pk_encrypt.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/pk_encrypt.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/pk_sign$(EXEXT): pkey/pk_sign.c ../library/libmbedtls.a
	echo   "  CC    pkey/pk_sign.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/pk_sign.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/pk_verify$(EXEXT): pkey/pk_verify.c ../library/libmbedtls.a
	echo   "  CC    pkey/pk_verify.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/pk_verify.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_genkey$(EXEXT): pkey/rsa_genkey.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_genkey.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_genkey.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_sign$(EXEXT): pkey/rsa_sign.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_sign.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_sign.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_verify$(EXEXT): pkey/rsa_verify.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_verify.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_verify.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_sign_pss$(EXEXT): pkey/rsa_sign_pss.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_sign_pss.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_sign_pss.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_verify_pss$(EXEXT): pkey/rsa_verify_pss.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_verify_pss.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_verify_pss.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_decrypt$(EXEXT): pkey/rsa_decrypt.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_decrypt.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_decrypt.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

pkey/rsa_encrypt$(EXEXT): pkey/rsa_encrypt.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_encrypt.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) pkey/rsa_encrypt.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

random/gen_entropy$(EXEXT): random/gen_entropy.c ../library/libmbedtls.a
	echo   "  CC    random/gen_entropy.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) random/gen_entropy.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

random/gen_random_havege$(EXEXT): random/gen_random_havege.c ../library/libmbedtls.a
	echo   "  CC    random/gen_random_havege.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) random/gen_random_havege.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

random/gen_random_ctr_drbg$(EXEXT): random/gen_random_ctr_drbg.c ../library/libmbedtls.a
	echo   "  CC    random/gen_random_ctr_drbg.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) random/gen_random_ctr_drbg.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_client1$(EXEXT): ssl/ssl_client1.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_client1.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_client1.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_client2$(EXEXT): ssl/ssl_client2.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_client2.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_client2.c  $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_server$(EXEXT): ssl/ssl_server.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_server.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_server.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_server2$(EXEXT): ssl/ssl_server2.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_server2.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_server2.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_fork_server$(EXEXT): ssl/ssl_fork_server.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_fork_server.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_fork_server.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/ssl_pthread_server$(EXEXT): ssl/ssl_pthread_server.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_pthread_server.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_pthread_server.c   $(LOCAL_LDFLAGS) -lpthread  $(LDFLAGS) -o $@

ssl/ssl_mail_client$(EXEXT): ssl/ssl_mail_client.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_mail_client.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/ssl_mail_client.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

ssl/mini_client$(EXEXT): ssl/mini_client.c ../library/libmbedtls.a
	echo   "  CC    ssl/mini_client.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) ssl/mini_client.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/ssl_cert_test$(EXEXT): test/ssl_cert_test.c ../library/libmbedtls.a
	echo   "  CC    test/ssl_cert_test.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/ssl_cert_test.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/benchmark$(EXEXT): test/benchmark.c ../library/libmbedtls.a
	echo   "  CC    test/benchmark.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/benchmark.c   $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/selftest$(EXEXT): test/selftest.c ../library/libmbedtls.a
	echo   "  CC    test/selftest.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/selftest.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/ssl_test$(EXEXT): test/ssl_test.c ../library/libmbedtls.a
	echo   "  CC    test/ssl_test.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/ssl_test.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

test/o_p_test$(EXEXT): test/o_p_test.c ../library/libmbedtls.a
	echo   "  CC    test/o_p_test.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) test/o_p_test.c    $(LOCAL_LDFLAGS) -lssl -lcrypto  $(LDFLAGS) -o $@

util/pem2der$(EXEXT): util/pem2der.c ../library/libmbedtls.a
	echo   "  CC    util/pem2der.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) util/pem2der.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

util/strerror$(EXEXT): util/strerror.c ../library/libmbedtls.a
	echo   "  CC    util/strerror.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) util/strerror.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/cert_app$(EXEXT): x509/cert_app.c ../library/libmbedtls.a
	echo   "  CC    x509/cert_app.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/cert_app.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/crl_app$(EXEXT): x509/crl_app.c ../library/libmbedtls.a
	echo   "  CC    x509/crl_app.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/crl_app.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

x509/cert_req$(EXEXT): x509/cert_req.c ../library/libmbedtls.a
	echo   "  CC    x509/cert_req.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) x509/cert_req.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

clean:
ifndef WINDOWS
	rm -f $(APPS)
endif
ifdef WINDOWS
	del /S /Q /F *.o *.exe
endif

list:
	echo $(APPS)
