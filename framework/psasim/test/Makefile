INCLUDE := -I../include/ -I./psa_manifest

.PHONY: all clean

all:
	psa_autogen manifest.json
	$(CC) psa_ff_bootstrap_TEST_PARTITION.c -lpsaff -o partition
	$(CC) client.c -lpsaff -o client

clean:
	rm -rf psa_manifest
	rm -f client partition psa_ff_bootstrap_TEST_PARTITION.c
