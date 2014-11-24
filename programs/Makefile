
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile on MinGW: add "-lws2_32" to LDFLAGS or define WINDOWS in your env
# To compile with PKCS11: add "-lpkcs11-helper" to LDFLAGS

CFLAGS	+= -I../include -D_FILE_OFFSET_BITS=64 -Wall -W -Wdeclaration-after-statement
OFLAGS	= -O2
LDFLAGS	+= -L../library -lmbedtls$(SHARED_SUFFIX) $(SYS_LDFLAGS)

ifdef DEBUG
CFLAGS += -g3
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
LDFLAGS += -lws2_32
ifdef SHARED
SHARED_SUFFIX=.$(DLEXT)
endif
endif

# Zlib shared library extensions:
ifdef ZLIB
LDFLAGS += -lz
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
	$(CC) $(CFLAGS) $(OFLAGS) aes/aescrypt2.c    $(LDFLAGS) -o $@

aes/crypt_and_hash$(EXEXT): aes/crypt_and_hash.c ../library/libmbedtls.a
	echo   "  CC    aes/crypt_and_hash.c"
	$(CC) $(CFLAGS) $(OFLAGS) aes/crypt_and_hash.c $(LDFLAGS) -o $@

hash/hello$(EXEXT): hash/hello.c ../library/libmbedtls.a
	echo   "  CC    hash/hello.c"
	$(CC) $(CFLAGS) $(OFLAGS) hash/hello.c       $(LDFLAGS) -o $@

hash/generic_sum$(EXEXT): hash/generic_sum.c ../library/libmbedtls.a
	echo   "  CC    hash/generic_sum.c"
	$(CC) $(CFLAGS) $(OFLAGS) hash/generic_sum.c $(LDFLAGS) -o $@

hash/md5sum$(EXEXT): hash/md5sum.c ../library/libmbedtls.a
	echo   "  CC    hash/md5sum.c"
	$(CC) $(CFLAGS) $(OFLAGS) hash/md5sum.c      $(LDFLAGS) -o $@

hash/sha1sum$(EXEXT): hash/sha1sum.c ../library/libmbedtls.a
	echo   "  CC    hash/sha1sum.c"
	$(CC) $(CFLAGS) $(OFLAGS) hash/sha1sum.c     $(LDFLAGS) -o $@

hash/sha2sum$(EXEXT): hash/sha2sum.c ../library/libmbedtls.a
	echo   "  CC    hash/sha2sum.c"
	$(CC) $(CFLAGS) $(OFLAGS) hash/sha2sum.c     $(LDFLAGS) -o $@

pkey/dh_client$(EXEXT): pkey/dh_client.c ../library/libmbedtls.a
	echo   "  CC    pkey/dh_client.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/dh_client.c   $(LDFLAGS) -o $@

pkey/dh_genprime$(EXEXT): pkey/dh_genprime.c ../library/libmbedtls.a
	echo   "  CC    pkey/dh_genprime.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/dh_genprime.c $(LDFLAGS) -o $@

pkey/dh_server$(EXEXT): pkey/dh_server.c ../library/libmbedtls.a
	echo   "  CC    pkey/dh_server.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/dh_server.c   $(LDFLAGS) -o $@

pkey/ecdsa$(EXEXT): pkey/ecdsa.c ../library/libmbedtls.a
	echo   "  CC    pkey/ecdsa.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/ecdsa.c       $(LDFLAGS) -o $@

pkey/gen_key$(EXEXT): pkey/gen_key.c ../library/libmbedtls.a
	echo   "  CC    pkey/gen_key.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/gen_key.c   $(LDFLAGS) -o $@

pkey/key_app$(EXEXT): pkey/key_app.c ../library/libmbedtls.a
	echo   "  CC    pkey/key_app.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/key_app.c   $(LDFLAGS) -o $@

pkey/key_app_writer$(EXEXT): pkey/key_app_writer.c ../library/libmbedtls.a
	echo   "  CC    pkey/key_app_writer.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/key_app_writer.c   $(LDFLAGS) -o $@

pkey/mpi_demo$(EXEXT): pkey/mpi_demo.c ../library/libmbedtls.a
	echo   "  CC    pkey/mpi_demo.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/mpi_demo.c    $(LDFLAGS) -o $@

pkey/pk_decrypt$(EXEXT): pkey/pk_decrypt.c ../library/libmbedtls.a
	echo   "  CC    pkey/pk_decrypt.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/pk_decrypt.c    $(LDFLAGS) -o $@

pkey/pk_encrypt$(EXEXT): pkey/pk_encrypt.c ../library/libmbedtls.a
	echo   "  CC    pkey/pk_encrypt.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/pk_encrypt.c    $(LDFLAGS) -o $@

pkey/pk_sign$(EXEXT): pkey/pk_sign.c ../library/libmbedtls.a
	echo   "  CC    pkey/pk_sign.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/pk_sign.c    $(LDFLAGS) -o $@

pkey/pk_verify$(EXEXT): pkey/pk_verify.c ../library/libmbedtls.a
	echo   "  CC    pkey/pk_verify.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/pk_verify.c  $(LDFLAGS) -o $@

pkey/rsa_genkey$(EXEXT): pkey/rsa_genkey.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_genkey.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/rsa_genkey.c  $(LDFLAGS) -o $@

pkey/rsa_sign$(EXEXT): pkey/rsa_sign.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_sign.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/rsa_sign.c    $(LDFLAGS) -o $@

pkey/rsa_verify$(EXEXT): pkey/rsa_verify.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_verify.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/rsa_verify.c  $(LDFLAGS) -o $@

pkey/rsa_sign_pss$(EXEXT): pkey/rsa_sign_pss.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_sign_pss.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/rsa_sign_pss.c    $(LDFLAGS) -o $@

pkey/rsa_verify_pss$(EXEXT): pkey/rsa_verify_pss.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_verify_pss.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/rsa_verify_pss.c  $(LDFLAGS) -o $@

pkey/rsa_decrypt$(EXEXT): pkey/rsa_decrypt.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_decrypt.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/rsa_decrypt.c    $(LDFLAGS) -o $@

pkey/rsa_encrypt$(EXEXT): pkey/rsa_encrypt.c ../library/libmbedtls.a
	echo   "  CC    pkey/rsa_encrypt.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/rsa_encrypt.c    $(LDFLAGS) -o $@

random/gen_entropy$(EXEXT): random/gen_entropy.c ../library/libmbedtls.a
	echo   "  CC    random/gen_entropy.c"
	$(CC) $(CFLAGS) $(OFLAGS) random/gen_entropy.c $(LDFLAGS) -o $@

random/gen_random_havege$(EXEXT): random/gen_random_havege.c ../library/libmbedtls.a
	echo   "  CC    random/gen_random_havege.c"
	$(CC) $(CFLAGS) $(OFLAGS) random/gen_random_havege.c $(LDFLAGS) -o $@

random/gen_random_ctr_drbg$(EXEXT): random/gen_random_ctr_drbg.c ../library/libmbedtls.a
	echo   "  CC    random/gen_random_ctr_drbg.c"
	$(CC) $(CFLAGS) $(OFLAGS) random/gen_random_ctr_drbg.c $(LDFLAGS) -o $@

ssl/ssl_client1$(EXEXT): ssl/ssl_client1.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_client1.c"
	$(CC) $(CFLAGS) $(OFLAGS) ssl/ssl_client1.c  $(LDFLAGS) -o $@

ssl/ssl_client2$(EXEXT): ssl/ssl_client2.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_client2.c"
	$(CC) $(CFLAGS) $(OFLAGS) ssl/ssl_client2.c  $(LDFLAGS) -o $@

ssl/ssl_server$(EXEXT): ssl/ssl_server.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_server.c"
	$(CC) $(CFLAGS) $(OFLAGS) ssl/ssl_server.c   $(LDFLAGS) -o $@

ssl/ssl_server2$(EXEXT): ssl/ssl_server2.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_server2.c"
	$(CC) $(CFLAGS) $(OFLAGS) ssl/ssl_server2.c   $(LDFLAGS) -o $@

ssl/ssl_fork_server$(EXEXT): ssl/ssl_fork_server.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_fork_server.c"
	$(CC) $(CFLAGS) $(OFLAGS) ssl/ssl_fork_server.c   $(LDFLAGS) -o $@

ssl/ssl_pthread_server$(EXEXT): ssl/ssl_pthread_server.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_pthread_server.c"
	$(CC) $(CFLAGS) $(OFLAGS) ssl/ssl_pthread_server.c   $(LDFLAGS) -o $@ -lpthread

ssl/ssl_mail_client$(EXEXT): ssl/ssl_mail_client.c ../library/libmbedtls.a
	echo   "  CC    ssl/ssl_mail_client.c"
	$(CC) $(CFLAGS) $(OFLAGS) ssl/ssl_mail_client.c   $(LDFLAGS) -o $@

ssl/mini_client$(EXEXT): ssl/mini_client.c ../library/libmbedtls.a
	echo   "  CC    ssl/mini_client.c"
	$(CC) $(CFLAGS) $(OFLAGS) ssl/mini_client.c   $(LDFLAGS) -o $@

test/ssl_cert_test$(EXEXT): test/ssl_cert_test.c ../library/libmbedtls.a
	echo   "  CC    test/ssl_cert_test.c"
	$(CC) $(CFLAGS) $(OFLAGS) test/ssl_cert_test.c   $(LDFLAGS) -o $@

test/benchmark$(EXEXT): test/benchmark.c ../library/libmbedtls.a
	echo   "  CC    test/benchmark.c"
	$(CC) $(CFLAGS) $(OFLAGS) test/benchmark.c   $(LDFLAGS) -o $@

test/selftest$(EXEXT): test/selftest.c ../library/libmbedtls.a
	echo   "  CC    test/selftest.c"
	$(CC) $(CFLAGS) $(OFLAGS) test/selftest.c    $(LDFLAGS) -o $@

test/ssl_test$(EXEXT): test/ssl_test.c ../library/libmbedtls.a
	echo   "  CC    test/ssl_test.c"
	$(CC) $(CFLAGS) $(OFLAGS) test/ssl_test.c    $(LDFLAGS) -o $@

test/o_p_test$(EXEXT): test/o_p_test.c ../library/libmbedtls.a
	echo   "  CC    test/o_p_test.c"
	$(CC) $(CFLAGS) $(OFLAGS) test/o_p_test.c    $(LDFLAGS) -o $@ -lssl -lcrypto

util/pem2der$(EXEXT): util/pem2der.c ../library/libmbedtls.a
	echo   "  CC    util/pem2der.c"
	$(CC) $(CFLAGS) $(OFLAGS) util/pem2der.c    $(LDFLAGS) -o $@

util/strerror$(EXEXT): util/strerror.c ../library/libmbedtls.a
	echo   "  CC    util/strerror.c"
	$(CC) $(CFLAGS) $(OFLAGS) util/strerror.c    $(LDFLAGS) -o $@

x509/cert_app$(EXEXT): x509/cert_app.c ../library/libmbedtls.a
	echo   "  CC    x509/cert_app.c"
	$(CC) $(CFLAGS) $(OFLAGS) x509/cert_app.c    $(LDFLAGS) -o $@

x509/crl_app$(EXEXT): x509/crl_app.c ../library/libmbedtls.a
	echo   "  CC    x509/crl_app.c"
	$(CC) $(CFLAGS) $(OFLAGS) x509/crl_app.c    $(LDFLAGS) -o $@

x509/cert_req$(EXEXT): x509/cert_req.c ../library/libmbedtls.a
	echo   "  CC    x509/cert_req.c"
	$(CC) $(CFLAGS) $(OFLAGS) x509/cert_req.c    $(LDFLAGS) -o $@

clean:
ifndef WINDOWS
	rm -f $(APPS)
endif
ifdef WINDOWS
	del /S /Q /F *.o *.exe
endif

list:
	echo $(APPS)
