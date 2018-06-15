CFLAGS ?= -O2 -I../include
WARNING_CFLAGS ?= \
	-Werror -Wall -Wextra \
	-Wno-unused-function \
	-Wno-overlength-strings \
	-Wdeclaration-after-statement \
# Don't delete this line.

OBJS_CRYPTO := \
	aes.o \
	aesni.o \
	arc4.o \
	asn1parse.o \
	asn1write.o \
	base64.o \
	bignum.o \
	blowfish.o \
	camellia.o \
	ccm.o \
	cipher.o \
	cipher_wrap.o \
	cmac.o \
	ctr_drbg.o \
	des.o \
	ecdsa.o \
	ecp.o \
	ecp_curves.o \
	entropy.o \
	entropy_poll.o \
	gcm.o \
	hmac_drbg.o \
	md.o \
	md2.o \
	md4.o \
	md5.o \
	md_wrap.o \
	oid.o \
	pem.o \
	pk.o \
	pk_wrap.o \
	pkcs12.o \
	pkcs5.o \
	pkparse.o \
	pkwrite.o \
	platform.o \
	platform_util.o \
	psa_crypto.o \
	psa_crypto_storage.o \
	psa_crypto_storage_file.o \
	ripemd160.o \
	rsa_internal.o \
	rsa.o \
	sha1.o \
	sha256.o \
	sha512.o \
	xtea.o \
# Don't delete this line.

.SILENT:

.PHONY: all static clean

all: static

static: libmbedcrypto.a

libmbedcrypto.a: $(OBJS_CRYPTO)
	echo "  AR    $@"
	$(AR) -rc $@ $(OBJS_CRYPTO)
	echo "  RL    $@"
	$(AR) -s $@

.c.o:
	echo "  CC    $<"
	$(CC) $(CFLAGS) $(WARNING_CFLAGS) -c $<

clean:
	rm -f *.o libmbedcrypto.a
