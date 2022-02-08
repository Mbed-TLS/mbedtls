# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS

# Set this to -v to see the details of failing test cases
TEST_FLAGS ?= $(if $(filter-out 0 OFF Off off NO No no FALSE False false N n,$(CTEST_OUTPUT_ON_FAILURE)),-v,)

tests/default: tests/all

tests/%: BUILD_DIR = tests

# Include public header files from ../include, test-specific header files
# from ./include, and private header files (used by some invasive tests)
# from ../library.
tests/%: LOCAL_CFLAGS += $(WARNING_CFLAGS) -I./include -I../include -I../library -D_FILE_OFFSET_BITS=64
tests/%: LOCAL_LDFLAGS := -L../library		\
		-lmbedtls$(SHARED_SUFFIX)	\
		-lmbedx509$(SHARED_SUFFIX)	\
		-lmbedcrypto$(SHARED_SUFFIX)	\
		$(LOCAL_LDFLAGS)

tests/%: LOCAL_CFLAGS+=$(THIRDPARTY_INCLUDES)

# Enable definition of various functions used throughout the testsuite
# (gethostname, strdup, fileno...) even when compiling with -std=c99. Harmless
# on non-POSIX platforms.
tests/%: LOCAL_CFLAGS += -D_POSIX_C_SOURCE=200809L

ifdef RECORD_PSA_STATUS_COVERAGE_LOG
tests/%: LOCAL_CFLAGS += -Werror -DRECORD_PSA_STATUS_COVERAGE_LOG
endif

.PHONY: tests/generated_files
GENERATED_DATA_FILES := $(shell \
	$(PYTHON) tests/scripts/generate_psa_tests.py --list || \
	echo FAILED \
)
ifeq ($(GENERATED_DATA_FILES),FAILED)
$(error "$(PYTHON) tests/scripts/generate_psa_tests.py --list" failed)
endif
GENERATED_FILES := $(GENERATED_DATA_FILES)
tests/generated_files: $(GENERATED_FILES)

# generate_psa_tests.py spends more time analyzing inputs than generating
# outputs. Its inputs are the same no matter which files are being generated.
# It's rare not to want all the outputs. So always generate all of its outputs.
# Use an intermediate phony dependency so that parallel builds don't run
# a separate instance of the recipe for each output file.
.SECONDARY: tests/generated_psa_test_data
$(GENERATED_DATA_FILES): tests/generated_psa_test_data
tests/generated_psa_test_data: tests/scripts/generate_psa_tests.py
## The generated file only depends on the options that are present in
## crypto_config.h, not on which options are set. To avoid regenerating this
## file all the time when switching between configurations, don't declare
## crypto_config.h as a dependency. Remove this file from your working tree
## if you've just added or removed an option in crypto_config.h.
#tests/generated_psa_test_data: include/psa/crypto_config.h
tests/generated_psa_test_data: include/psa/crypto_values.h
tests/generated_psa_test_data: include/psa/crypto_extra.h
tests/generated_psa_test_data: tests/suites/test_suite_psa_crypto_metadata.data
tests/generated_psa_test_data:
	echo "  Gen   $(GENERATED_DATA_FILES) ..."
	$(PYTHON) tests/scripts/generate_psa_tests.py

# A test application is built for each suites/test_suite_*.data file.
# Application name is same as .data file's base name and can be
# constructed by stripping path 'suites/' and extension .data.
DATA_FILES := $(wildcard tests/suites/test_suite_*.data)
# Make sure that generated data files are included even if they don't
# exist yet when the makefile is parsed.
DATA_FILES += $(filter-out $(DATA_FILES),$(GENERATED_DATA_FILES))
APPS = $(basename $(patsubst tests/suites/%,tests/%,$(DATA_FILES)))

# Construct executable name by adding OS specific suffix $(EXEXT).
BINARIES := $(addsuffix $(EXEXT),$(APPS))

.PHONY: tests/all tests/check tests/test tests/clean

tests/all: $(BINARIES)

MBEDTLS_TEST_SRC_OBJS=$(patsubst %.c,%.o,$(wildcard tests/src/*.c))
MBEDTLS_TEST_OBJS=$(MBEDTLS_TEST_SRC_OBJS) $(patsubst %.c,%.o,$(wildcard tests/src/drivers/*.c))

tests/mbedtls_test: $(MBEDTLS_TEST_OBJS)

TEST_OBJS_DEPS = $(wildcard tests/include/test/*.h tests/include/test/*/*.h)
ifdef RECORD_PSA_STATUS_COVERAGE_LOG
# Explicitly depend on this header because on a clean copy of the source tree,
# it doesn't exist yet and must be generated as part of the build, and
# therefore the wildcard enumeration above doesn't include it.
TEST_OBJS_DEPS += tests/include/test/instrument_record_status.h
endif

# Add dependencies for common test files in src folder
$(MBEDTLS_TEST_SRC_OBJS): $(TEST_OBJS_DEPS)

C_FILES := $(addsuffix .c,$(APPS))

# Wildcard target for test code generation:
# A .c file is generated for each .data file in the suites/ directory. Each .c
# file depends on a .data and .function file from suites/ directory. Following
# nameing convention is followed:
#
#     C file        |        Depends on
#-----------------------------------------------------------------------------
#  foo.c            | suites/foo.function suites/foo.data
#  foo.bar.c        | suites/foo.function suites/foo.bar.data
#
# Note above that .c and .data files have same base name.
# However, corresponding .function file's base name is the word before first
# dot in .c file's base name.
#
.SECONDEXPANSION:
tests/%.c: tests/suites/$$(firstword $$(subst ., ,$$*)).function tests/suites/%.data tests/scripts/generate_test_code.py tests/suites/helpers.function tests/suites/main_test.function tests/suites/host_test.function
	echo "  Gen   $@"
	cd tests && $(PYTHON) scripts/generate_test_code.py -f suites/$(firstword $(subst ., ,$*)).function \
		-d suites/$*.data \
		-t suites/main_test.function \
		-p suites/host_test.function \
		-s suites  \
		--helpers-file suites/helpers.function \
		-o .


$(BINARIES): %$(EXEXT): %.c $(MBEDLIBS) $(MBEDTLS_TEST_OBJS)
	echo "  CC    $<"
	cd $(BUILD_DIR) && $(CC) $(LOCAL_CFLAGS) $(CFLAGS) $(abspath $<) $(abspath $(MBEDTLS_TEST_OBJS)) $(LOCAL_LDFLAGS) $(LDFLAGS) -o $(abspath $@)

tests/clean:
ifndef WINDOWS
	rm -rf $(BINARIES) tests/*.c tests/*.datax
	rm -f tests/src/*.o tests/src/drivers/*.o tests/src/libmbed*
	rm -f tests/include/test/instrument_record_status.h
	rm -rf tests/libtestdriver1
else
	if exist tests/*.c del /Q /F tests/*.c
	if exist tests/*.exe del /Q /F tests/*.exe
	if exist tests/*.datax del /Q /F tests/*.datax
	if exist tests/src/*.o del /Q /F tests/src/*.o
	if exist tests/src/drivers/*.o del /Q /F tests/src/drivers/*.o
	if exist tests/src/libmbed* del /Q /F tests/src/libmed*
	if exist tests/include/test/instrument_record_status.h del /Q /F tests/include/test/instrument_record_status.h
endif

tests/neat: tests/clean
ifndef WINDOWS
	rm -f $(GENERATED_FILES)
else
	for %%f in ($(subst /,\,$(GENERATED_FILES))) do if exist %%f del /Q /F %%f
endif

# Test suites caught by SKIP_TEST_SUITES are built but not executed.
tests/check: $(BINARIES)
	cd tests && perl scripts/run-test-suites.pl $(TEST_FLAGS) --skip=$(SKIP_TEST_SUITES)

tests/test: tests/check

# Generate test library

# Perl code that is executed to transform each original line from a library
# source file into the corresponding line in the test driver copy of the
# library. Add a LIBTESTDRIVER1_/libtestdriver1_ to mbedtls_xxx and psa_xxx
# symbols.
define libtestdriver1_rewrite :=
	s!^(\s*#\s*include\s*[\"<])(mbedtls|psa)/!$${1}libtestdriver1/include/$${2}/!; \
	next if /^\s*#\s*include/; \
	s/\b(?=MBEDTLS_|PSA_)/LIBTESTDRIVER1_/g; \
	s/\b(?=mbedtls_|psa_)/libtestdriver1_/g;
endef

tests/libtestdriver1.a:
	# Copy the library and fake a 3rdparty Makefile include.
	rm -Rf tests/libtestdriver1
	mkdir tests/libtestdriver1
	cp -f Makefile tests/libtestdriver1
	cp -Rf library tests/libtestdriver1
	cp -Rf include tests/libtestdriver1
	cp -Rf scripts tests/libtestdriver1
	mkdir tests/libtestdriver1/3rdparty
	touch tests/libtestdriver1/3rdparty/Makefile.inc
	mkdir tests/libtestdriver1/tests
	touch tests/libtestdriver1/tests/Makefile.inc

	# Set the test driver base (minimal) configuration.
	cp tests/include/test/drivers/config_test_driver.h tests/libtestdriver1/include/mbedtls/mbedtls_config.h

	# Set the PSA cryptography configuration for the test library.
	# It is set from the copied include/psa/crypto_config.h of the Mbed TLS
        # library the test library is intended to be linked with extended by
        # tests/include/test/drivers/crypto_config_test_driver_extension.h to
        # mirror the PSA_ACCEL_* macros.
	mv tests/libtestdriver1/include/psa/crypto_config.h tests/libtestdriver1/include/psa/crypto_config.h.bak
	head -n -1 tests/libtestdriver1/include/psa/crypto_config.h.bak > tests/libtestdriver1/include/psa/crypto_config.h
	cat tests/include/test/drivers/crypto_config_test_driver_extension.h >> tests/libtestdriver1/include/psa/crypto_config.h
	echo "#endif /* PSA_CRYPTO_CONFIG_H */" >> tests/libtestdriver1/include/psa/crypto_config.h

	# Prefix MBEDTLS_* PSA_* symbols with LIBTESTDRIVER1_ as well as
	# mbedtls_* psa_* symbols with libtestdriver1_ to avoid symbol clash
	# when this test driver library is linked with the Mbed TLS library.
	perl -pi -e '$(libtestdriver1_rewrite)' tests/libtestdriver1/library/*.[ch]
	perl -pi -e '$(libtestdriver1_rewrite)' tests/libtestdriver1/include/*/*.h

	$(MAKE) -C tests/libtestdriver1 CFLAGS="-I../../ $(CFLAGS)" LDFLAGS="$(LDFLAGS)" library/libmbedcrypto.a
	cp tests/libtestdriver1/library/libmbedcrypto.a library/libtestdriver1.a

ifdef RECORD_PSA_STATUS_COVERAGE_LOG
tests/include/test/instrument_record_status.h: include/psa/crypto.h tests/Makefile
	echo "  Gen  $@"
	sed <include/psa/crypto.h >$@ -n 's/^psa_status_t \([A-Za-z0-9_]*\)(.*/#define \1(...) RECORD_STATUS("\1", \1(__VA_ARGS__))/p'
endif
