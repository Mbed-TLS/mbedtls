MBEDTLS_TEST_PATH:=../../tests

MBEDTLS_PATH := ../..
include ../../scripts/common.make

DEP=${MBEDLIBS}

ifdef FUZZINGENGINE
LOCAL_LDFLAGS += -lFuzzingEngine
endif

LOCAL_CFLAGS += -I$(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/

# A test application is built for each fuzz_*.c file.
APPS = $(basename $(wildcard fuzz_*.c))
APPS += $(basename $(wildcard $(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/fuzz_privkey.c))
APPS += $(basename $(wildcard $(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/fuzz_pubkey.c))

# Construct executable name by adding OS specific suffix $(EXEXT).
BINARIES := $(addsuffix $(EXEXT),$(APPS))

.SILENT:

.PHONY: all check test clean

all: $(BINARIES)

C_FILES := $(addsuffix .c,$(APPS))

%.o: %.c
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -c $<	-o $@


ifdef FUZZINGENGINE
$(BINARIES): %$(EXEXT): %.o $(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/fuzz_common.o $(DEP)
	echo " $(CC) $(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/fuzz_common.o $< $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@"
	$(CXX) $(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/fuzz_common.o $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@
else
$(BINARIES): %$(EXEXT): %.o $(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/fuzz_common.o $(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/onefile.o $(DEP)
	echo " $(CC) $(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/fuzz_common.o $(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/onefile.o $< $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@"
	$(CC) $(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/fuzz_common.o $(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/onefile.o $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@
endif

clean:
ifndef WINDOWS
	rm -rf $(BINARIES) *.o
	rm -rf $(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/*.o
else
	if exist *.o del /Q /F *.o
	if exist *.exe del /Q /F *.exe
	rm -rf $(MBEDTLS_PATH)/tf-psa-crypto/programs/fuzz/*.o
endif
