CFLAGS += -Wall -Werror -std=c99 -D_XOPEN_SOURCE=1 -D_POSIX_C_SOURCE=200809L

ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG -O0 -g
endif

LIBPSACLIENT := -Llibpsaclient/ -lmbedcrypto -lmbedx509 -lmbedtls
LIBPSASERVER := -Llibpsaserver/ -lmbedcrypto

MBEDTLS_ROOT_PATH = ../../..
COMMON_INCLUDE := -I./include -I$(MBEDTLS_ROOT_PATH)/include -I$(MBEDTLS_ROOT_PATH)/tf-psa-crypto/include

GENERATED_H_FILES =	include/psa_manifest/manifest.h \
					include/psa_manifest/pid.h \
					include/psa_manifest/sid.h

PSA_CLIENT_COMMON_SRC = src/psa_ff_client.c \
		 src/psa_sim_crypto_client.c \
		 src/psa_sim_serialise.c

PSA_CLIENT_BASE_SRC = $(PSA_CLIENT_COMMON_SRC) src/client.c

PSA_CLIENT_FULL_SRC = $(PSA_CLIENT_COMMON_SRC) \
				$(wildcard src/aut_*.c)

PARTITION_SERVER_BOOTSTRAP = src/psa_ff_bootstrap_TEST_PARTITION.c

PSA_SERVER_SRC = $(PARTITION_SERVER_BOOTSTRAP) \
				 src/psa_ff_server.c \
				 src/psa_sim_crypto_server.c \
				 src/psa_sim_serialise.c

.PHONY: all clean libpsaclient libpsaserver

all:

test/seedfile:
	dd if=/dev/urandom of=./test/seedfile bs=64 count=1

test/psa_client_base: $(PSA_CLIENT_BASE_SRC) $(GENERATED_H_FILES)
	$(CC) $(COMMON_INCLUDE) $(CFLAGS) $(PSA_CLIENT_BASE_SRC) $(LIBPSACLIENT) $(LDFLAGS) -o $@

test/psa_client_full: $(PSA_CLIENT_FULL_SRC) $(GENERATED_H_FILES)
	$(CC) $(COMMON_INCLUDE) $(CFLAGS) $(PSA_CLIENT_FULL_SRC) $(LIBPSACLIENT) $(LDFLAGS) -o $@

test/psa_partition: $(PSA_SERVER_SRC) $(GENERATED_H_FILES) test/seedfile
	$(CC) $(COMMON_INCLUDE) $(CFLAGS) $(PSA_SERVER_SRC) $(LIBPSASERVER) $(LDFLAGS) -o $@

$(PARTITION_SERVER_BOOTSTRAP) $(GENERATED_H_FILES): src/manifest.json src/server.c
	tools/psa_autogen.py src/manifest.json

# Build MbedTLS libraries (crypto, x509 and tls) and copy them locally to
# build client/server applications.
#
# Note: these rules assume that mbedtls_config.h is already configured by all.sh.
# If not using all.sh then the user must do it manually.
libpsaclient libpsaserver:
	$(MAKE) -C $(MBEDTLS_ROOT_PATH)/library CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" libmbedcrypto.a libmbedx509.a libmbedtls.a
	mkdir -p $@
	cp $(MBEDTLS_ROOT_PATH)/library/libmbed*.a $@/
	$(MAKE) -C $(MBEDTLS_ROOT_PATH) clean

clean:
	rm -f test/psa_client_base test/psa_client_full test/psa_partition
	rm -f $(PARTITION_SERVER_BOOTSTRAP)
	rm -rf libpsaclient libpsaserver
	rm -rf include/psa_manifest
	rm -f test/psa_service_* test/psa_notify_*
	rm -f test/*.log
	rm -f test/seedfile
