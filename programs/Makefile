
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile on MinGW: add "-lws2_32" to LDFLAGS

CFLAGS	= -I../include -D_FILE_OFFSET_BITS=64 -Wall -Wdeclaration-after-statement
OFLAGS	= -O
LDFLAGS	= -L../library -lpolarssl

APPS =	aes/aescrypt2		hash/hello		\
	hash/md5sum			hash/sha1sum		\
	hash/sha2sum		pkey/dh_client		\
	pkey/dh_genprime	pkey/dh_server		\
	pkey/mpi_demo		pkey/rsa_genkey		\
	pkey/rsa_sign		pkey/rsa_verify		\
	ssl/ssl_client1		ssl/ssl_client2		\
	ssl/ssl_server		test/ssl_cert_test	\
	test/benchmark		test/selftest		\
	test/ssl_test		x509/cert_app

.SILENT:

all: $(APPS)

aes/aescrypt2: aes/aescrypt2.c ../library/libpolarssl.a
	echo   "  CC    aes/aescrypt2.c"
	$(CC) $(CFLAGS) $(OFLAGS) aes/aescrypt2.c    $(LDFLAGS) -o $@

hash/hello: hash/hello.c ../library/libpolarssl.a
	echo   "  CC    hash/hello.c"
	$(CC) $(CFLAGS) $(OFLAGS) hash/hello.c       $(LDFLAGS) -o $@

hash/md5sum: hash/md5sum.c ../library/libpolarssl.a
	echo   "  CC    hash/md5sum.c"
	$(CC) $(CFLAGS) $(OFLAGS) hash/md5sum.c      $(LDFLAGS) -o $@

hash/sha1sum: hash/sha1sum.c ../library/libpolarssl.a
	echo   "  CC    hash/sha1sum.c"
	$(CC) $(CFLAGS) $(OFLAGS) hash/sha1sum.c     $(LDFLAGS) -o $@

hash/sha2sum: hash/sha2sum.c ../library/libpolarssl.a
	echo   "  CC    hash/sha2sum.c"
	$(CC) $(CFLAGS) $(OFLAGS) hash/sha2sum.c     $(LDFLAGS) -o $@

pkey/dh_client: pkey/dh_client.c ../library/libpolarssl.a
	echo   "  CC    pkey/dh_client.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/dh_client.c   $(LDFLAGS) -o $@

pkey/dh_genprime: pkey/dh_genprime.c ../library/libpolarssl.a
	echo   "  CC    pkey/dh_genprime.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/dh_genprime.c $(LDFLAGS) -o $@

pkey/dh_server: pkey/dh_server.c ../library/libpolarssl.a
	echo   "  CC    pkey/dh_server.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/dh_server.c   $(LDFLAGS) -o $@

pkey/mpi_demo: pkey/mpi_demo.c ../library/libpolarssl.a
	echo   "  CC    pkey/mpi_demo.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/mpi_demo.c    $(LDFLAGS) -o $@

pkey/rsa_genkey: pkey/rsa_genkey.c ../library/libpolarssl.a
	echo   "  CC    pkey/rsa_genkey.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/rsa_genkey.c  $(LDFLAGS) -o $@

pkey/rsa_sign: pkey/rsa_sign.c ../library/libpolarssl.a
	echo   "  CC    pkey/rsa_sign.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/rsa_sign.c    $(LDFLAGS) -o $@

pkey/rsa_verify: pkey/rsa_verify.c ../library/libpolarssl.a
	echo   "  CC    pkey/rsa_verify.c"
	$(CC) $(CFLAGS) $(OFLAGS) pkey/rsa_verify.c  $(LDFLAGS) -o $@

ssl/ssl_client1: ssl/ssl_client1.c ../library/libpolarssl.a
	echo   "  CC    ssl/ssl_client1.c"
	$(CC) $(CFLAGS) $(OFLAGS) ssl/ssl_client1.c  $(LDFLAGS) -o $@

ssl/ssl_client2: ssl/ssl_client2.c ../library/libpolarssl.a
	echo   "  CC    ssl/ssl_client2.c"
	$(CC) $(CFLAGS) $(OFLAGS) ssl/ssl_client2.c  $(LDFLAGS) -o $@

ssl/ssl_server: ssl/ssl_server.c ../library/libpolarssl.a
	echo   "  CC    ssl/ssl_server.c"
	$(CC) $(CFLAGS) $(OFLAGS) ssl/ssl_server.c   $(LDFLAGS) -o $@

test/ssl_cert_test: test/ssl_cert_test.c ../library/libpolarssl.a
	echo   "  CC    test/ssl_cert_test.c"
	$(CC) $(CFLAGS) $(OFLAGS) test/ssl_cert_test.c   $(LDFLAGS) -o $@

test/benchmark: test/benchmark.c ../library/libpolarssl.a
	echo   "  CC    test/benchmark.c"
	$(CC) $(CFLAGS) $(OFLAGS) test/benchmark.c   $(LDFLAGS) -o $@

test/selftest: test/selftest.c ../library/libpolarssl.a
	echo   "  CC    test/selftest.c"
	$(CC) $(CFLAGS) $(OFLAGS) test/selftest.c    $(LDFLAGS) -o $@

test/ssl_test: test/ssl_test.c ../library/libpolarssl.a
	echo   "  CC    test/ssl_test.c"
	$(CC) $(CFLAGS) $(OFLAGS) test/ssl_test.c    $(LDFLAGS) -o $@

x509/cert_app: x509/cert_app.c ../library/libpolarssl.a
	echo   "  CC    x509/cert_app.c"
	$(CC) $(CFLAGS) $(OFLAGS) x509/cert_app.c    $(LDFLAGS) -o $@

clean:
	rm -f $(APPS)

