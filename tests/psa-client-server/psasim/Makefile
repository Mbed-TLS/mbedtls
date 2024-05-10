CFLAGS += -Wall -Werror -std=c99 -D_XOPEN_SOURCE=1 -D_POSIX_C_SOURCE=200809L

ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG
endif

LIBPSACLIENT_PATH := ../../libpsaclient
LIBPSASERVER_PATH := ../../libpsaserver

LIBPSACLIENT := -L$(LIBPSACLIENT_PATH)/library -lmbedcrypto -lmbedx509 -lmbedtls
LIBPSASERVER := -L$(LIBPSASERVER_PATH)/library -lmbedcrypto

LIBPSACLIENT_H := -I$(LIBPSACLIENT_PATH)/include
LIBPSASERVER_H := -I$(LIBPSASERVER_PATH)/include

COMMON_INCLUDE := -I./include

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

.PHONY: all clean

all: $(TEST_BIN)

test/psa_client: $(PSA_CLIENT_SRC) $(GENERATED_H_FILES)
	$(CC) $(COMMON_INCLUDE) $(LIBPSACLIENT_H) $(CFLAGS) $(PSA_CLIENT_SRC) $(LIBPSACLIENT) $(LDFLAGS) -o $@

test/psa_partition: $(PSA_SERVER_SRC) $(GENERATED_H_FILES)
	$(CC) $(COMMON_INCLUDE) $(LIBPSASERVER_H) $(CFLAGS) $(PSA_SERVER_SRC) $(LIBPSASERVER) $(LDFLAGS) -o $@

$(PARTITION_SERVER_BOOTSTRAP) $(GENERATED_H_FILES): src/manifest.json src/server.c
	tools/psa_autogen.py src/manifest.json

clean:
	rm -f $(TEST_BIN)
	rm -f $(PARTITION_SERVER_BOOTSTRAP)
	rm -rf include/psa_manifest
	rm -f test/psa_service_* test/psa_notify_*

