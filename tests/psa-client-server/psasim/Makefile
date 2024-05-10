CFLAGS += -Wall -Werror -std=c99 -D_XOPEN_SOURCE=1 -D_POSIX_C_SOURCE=200809L

ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG
endif

LIBPSACLIENT := -Llibpsaclient/ -lmbedcrypto -lmbedx509 -lmbedtls
LIBPSASERVER := -Llibpsaserver/ -lmbedcrypto

MBEDTLS_ROOT_PATH = ../../..
COMMON_INCLUDE := -I./include -I$(MBEDTLS_ROOT_PATH)/include

TEST_BIN = 	test/psa_client \
			test/psa_partition

GENERATED_H_FILES =	include/psa_manifest/manifest.h \
					include/psa_manifest/pid.h \
					include/psa_manifest/sid.h

PSA_CLIENT_SRC = src/psa_ff_client.c \
				 src/client.c

PARTITION_SERVER_BOOTSTRAP = src/psa_ff_bootstrap_TEST_PARTITION.c

PSA_SERVER_SRC = $(PARTITION_SERVER_BOOTSTRAP) \
				 src/psa_ff_server.c

.PHONY: all clean libpsaclient libpsaserver

all: $(TEST_BIN)

test/psa_client: $(PSA_CLIENT_SRC) $(GENERATED_H_FILES)
	$(CC) $(COMMON_INCLUDE) $(CFLAGS) $(PSA_CLIENT_SRC) $(LIBPSACLIENT) $(LDFLAGS) -o $@

test/psa_partition: $(PSA_SERVER_SRC) $(GENERATED_H_FILES)
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
	rm -f $(TEST_BIN)
	rm -f $(PARTITION_SERVER_BOOTSTRAP)
	rm -rf libpsaclient libpsaserver
	rm -rf include/psa_manifest
	rm -f test/psa_service_* test/psa_notify_*

