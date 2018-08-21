CFLAGS ?= -O2 -I../include
WARNING_CFLAGS ?= \
	-Werror -Wall -Wextra \
	-Wno-unused-function \
	-Wno-overlength-strings \
	-Wdeclaration-after-statement \
# Don't delete this line.

LDFLAGS ?= -L../library -lmbedcrypto

DEP := ../library/libmbedcrypto.a

# Python executable
PYTHON ?= python

APPS := \
	test_suite_psa_crypto \
	test_suite_psa_crypto_metadata \
# Don't delete this line.

# Look up for associated function files
func.test_suite_psa_crypto := test_suite_psa_crypto
func.test_suite_psa_crypto_metadata := test_suite_psa_crypto_metadata

.SILENT:

.PHONY: all test clean

all: $(APPS)

$(DEP):
	$(MAKE) -C ../library

C_FILES := $(addsuffix .c,$(APPS))

.SECONDEXPANSION:
$(C_FILES): %.c: suites/$$(func.$$*).function suites/%.data scripts/generate_test_code.py suites/helpers.function suites/main_test.function suites/host_test.function
	echo "  Gen   $@"
	$(PYTHON) scripts/generate_test_code.py -f suites/$(func.$*).function \
		-d suites/$*.data \
		-t suites/main_test.function \
		-p suites/host_test.function \
		-s suites  \
		--help-file suites/helpers.function \
		-o .


$(APPS): %: %.c $(DEP)
	echo "  CC    $<"
	$(CC) $(CFLAGS) $(WARNING_CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -rf $(APPS) *.c *.data TESTS
	rm -rf data_files/ctr_drbg_seed data_files/hmac_drbg_seed data_files/mpi_write

test: $(APPS)
	./test_suite_psa_crypto_metadata
	./test_suite_psa_crypto

# Create separate targets for generating embedded tests.
EMBEDDED_TESTS := $(addprefix embedded_,$(APPS))

# Generate test code for target.

.SECONDEXPANSION:
$(EMBEDDED_TESTS): embedded_%: suites/$$(func.$$*).function suites/%.data scripts/generate_test_code.py suites/helpers.function suites/main_test.function suites/target_test.function
	echo "  Gen  ./TESTS/mbedcrypto/$*/$*.c"
	$(PYTHON) scripts/generate_test_code.py -f suites/$(func.$*).function \
		-d suites/$*.data \
		-t suites/main_test.function \
		-p suites/target_test.function \
		-s suites  \
		--help-file suites/helpers.function \
		-o ./TESTS/mbedcrypto/$*

gen-embedded-test: $(EMBEDDED_TESTS)
