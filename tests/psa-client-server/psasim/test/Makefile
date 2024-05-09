LIBPSASIM_PATH := ..
LIBPSACLIENT_PATH := ../../../libpsaclient
LIBPSASERVER_PATH := ../../../libpsaserver

LIBPSASIM := -L$(LIBPSASIM_PATH)/src -lpsaff
LIBPSACLIENT := -L$(LIBPSACLIENT_PATH)/library -lmbedcrypto -lmbedx509 -lmbedtls
LIBPSASERVER := -L$(LIBPSASERVER_PATH)/library -lmbedcrypto

LIBPSASIM_H := -I$(LIBPSASIM_PATH)/include
LIBPSACLIENT_H := -I$(LIBPSACLIENT_PATH)/include
LIBPSASERVER_H := -I$(LIBPSASERVER_PATH)/include

COMMON_INCLUDE := $(LIBPSASIM_H) -I./psa_manifest

TEST_BIN = 	psa_client \
			psa_partition

GENERATED_H_FILES =	psa_manifest/manifest.h \
					psa_manifest/pid.h \
					psa_manifest/sid.h

PARTITION_SERVER_BOOTSTRAP = psa_ff_bootstrap_TEST_PARTITION.c

.PHONY: all clean

all: $(TEST_BIN)

psa_client: client.c $(GENERATED_H_FILES)
	$(CC) $(COMMON_INCLUDE) $(LIBPSACLIENT_H) $(CFLAGS) $< $(LIBPSASIM) $(LIBPSACLIENT) $(LDFLAGS) -o $@

psa_partition: $(PARTITION_SERVER_BOOTSTRAP) $(GENERATED_H_FILES)
	$(CC) $(COMMON_INCLUDE) $(LIBPSASERVER_H) $(CFLAGS) $< $(LIBPSASIM) $(LIBPSASERVER) $(LDFLAGS) -o $@

$(PARTITION_SERVER_BOOTSTRAP) $(GENERATED_H_FILES): manifest.json server.c
	../tools/psa_autogen.py $<

clean:
	rm -f $(TEST_BIN) psa_ff_bootstrap_*.c
	rm -f psa_notify_* psa_service_*
	rm -f psa_manifest/*
