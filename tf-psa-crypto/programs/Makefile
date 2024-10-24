MBEDTLS_TEST_PATH = ../tests
include ../../scripts/common.make

ifdef RECORD_PSA_STATUS_COVERAGE_LOG
LOCAL_CFLAGS += -Werror -DRECORD_PSA_STATUS_COVERAGE_LOG
endif
DEP=${MBEDLIBS} ${MBEDTLS_TEST_OBJS}

APPS = \
	psa/aead_demo \
	psa/crypto_examples \
	psa/hmac_demo \
	psa/key_ladder_demo \
	psa/psa_constant_names \
	psa/psa_hash \
# End of APPS

EXES = $(patsubst %,%$(EXEXT),$(APPS))

.SILENT:

.PHONY: all clean list fuzz

all: $(EXES)
ifndef WINDOWS
# APPS doesn't include the fuzzing programs, which aren't "normal"
# sample or test programs, and don't build with MSVC which is
# warning about fopen
all: fuzz
endif

.PHONY: generated_files
GENERATED_FILES = psa/psa_constant_names_generated.c 
generated_files: $(GENERATED_FILES)

psa/psa_constant_names_generated.c: $(gen_file_dep) ../scripts/generate_psa_constants.py
psa/psa_constant_names_generated.c: $(gen_file_dep) ../tf-psa-crypto/include/psa/crypto_values.h
psa/psa_constant_names_generated.c: $(gen_file_dep) ../tf-psa-crypto/include/psa/crypto_extra.h
psa/psa_constant_names_generated.c: $(gen_file_dep) ../tf-psa-crypto/tests/suites/test_suite_psa_crypto_metadata.data
psa/psa_constant_names_generated.c:
	echo "  Gen   $@"
	$(PYTHON) ../scripts/generate_psa_constants.py

psa/aead_demo$(EXEXT): psa/aead_demo.c $(DEP)
	echo "  CC    psa/aead_demo.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) psa/aead_demo.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

psa/crypto_examples$(EXEXT): psa/crypto_examples.c $(DEP)
	echo "  CC    psa/crypto_examples.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) psa/crypto_examples.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

psa/hmac_demo$(EXEXT): psa/hmac_demo.c $(DEP)
	echo "  CC    psa/hmac_demo.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) psa/hmac_demo.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

psa/key_ladder_demo$(EXEXT): psa/key_ladder_demo.c $(DEP)
	echo "  CC    psa/key_ladder_demo.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) psa/key_ladder_demo.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

psa/psa_constant_names$(EXEXT): psa/psa_constant_names.c psa/psa_constant_names_generated.c $(DEP)
	echo "  CC    psa/psa_constant_names.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) psa/psa_constant_names.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

psa/psa_hash$(EXEXT): psa/psa_hash.c $(DEP)
	echo "  CC    psa/psa_hash.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) psa/psa_hash.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

clean:
ifndef WINDOWS
	rm -f $(EXES)
	rm -f */*.o
	-rm -f ssl/ssl_pthread_server$(EXEXT)
	-rm -f test/cpp_dummy_build.cpp test/cpp_dummy_build$(EXEXT)
	-rm -f test/dlopen$(EXEXT)
else
	if exist *.o del /Q /F *.o
	if exist *.exe del /Q /F *.exe
	if exist test\cpp_dummy_build.cpp del /Q /F test\cpp_dummy_build.cpp
endif
	$(MAKE) -C fuzz clean

list:
	echo $(EXES)
