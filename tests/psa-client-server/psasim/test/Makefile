INCLUDE := -I../include/ -I./psa_manifest
LIB := -L../src -lpsaff

TEST_BIN = 	psa_client \
			psa_partition

GENERATED_H_FILES =	psa_manifest/manifest.h \
					psa_manifest/pid.h \
					psa_manifest/sid.h

PARTITION_SERVER_BOOTSTRAP = psa_ff_bootstrap_TEST_PARTITION.c

.PHONY: all clean

all: $(TEST_BIN)

psa_client: client.c $(GENERATED_H_FILES)
	$(CC) $(INCLUDE) $(CFLAGS) $< $(LIB) -o $@

psa_partition: $(PARTITION_SERVER_BOOTSTRAP) $(GENERATED_H_FILES)
	$(CC) $(INCLUDE) $(CFLAGS) $< $(LIB) -o $@

$(PARTITION_SERVER_BOOTSTRAP) $(GENERATED_H_FILES): manifest.json server.c
	../tools/psa_autogen.py $<

clean:
	rm -f $(TEST_BIN) psa_ff_bootstrap_*.c
	rm -f psa_notify_* psa_service_*
	rm -f psa_manifest/*
