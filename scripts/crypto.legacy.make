# Helper code for the make build system in Mbed TLS.
# This file is only meant to exist for a short transition period.
# It may change or be removed without notice.
# Do not use it if you are not Mbed TLS!

# Assume that this makefile is located in a first-level subdirectory of the
# Mbed TLS root, and is accessed directly (not via VPATH or such).
# If this is not the case, TF_PSA_CRYPTO_PATH or MBEDTLS_PATH must be defined
# before including this file.
ifneq ($(origin TF_PSA_CRYPTO_PATH), undefined)
  # TF_PSA_CRYPTO_PATH was defined before including this file, good.
else ifneq ($(origin MBEDTLS_PATH), undefined)
  TF_PSA_CRYPTO_PATH := $(MBEDTLS_PATH)/tf-psa-crypto
else
  # $(dir $(lastword $(MAKEFILE_LIST))) is the path to this file, possibly
  # a relative path, with a trailing slash. Strip off another directory
  # from that.
  TF_PSA_CRYPTO_PATH := $(patsubst %/,%,$(dir $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))))/tf-psa-crypto
endif

ifeq (,$(wildcard $(TF_PSA_CRYPTO_PATH)/core/psa_crypto.c))
  $(error $$(TF_PSA_CRYPTO_PATH)/core/psa_crypto.c not found)
endif

THIRDPARTY_DIR := $(TF_PSA_CRYPTO_PATH)/drivers
include $(TF_PSA_CRYPTO_PATH)/drivers/everest/Makefile.inc
include $(TF_PSA_CRYPTO_PATH)/drivers/p256-m/Makefile.inc

# Directories with headers of public interfaces of TF-PSA-Crypto
TF_PSA_CRYPTO_LIBRARY_PUBLIC_INCLUDE = \
	-I$(TF_PSA_CRYPTO_PATH)/include \
	-I$(TF_PSA_CRYPTO_PATH)/drivers/builtin/include \
	$(THIRDPARTY_INCLUDES)

# Directories with headers of internal interfaces of TF-PSA-Crypto
# (currently consumed by Mbed TLS, eventually not so when we've finished
# cleaning up)
TF_PSA_CRYPTO_LIBRARY_PRIVATE_INCLUDE = \
	-I$(TF_PSA_CRYPTO_PATH)/core \
	-I$(TF_PSA_CRYPTO_PATH)/drivers/builtin/src

## Usage: $(call remove_enabled_options_crypto,PREPROCESSOR_INPUT)
## Remove the preprocessor symbols that are set in the current configuration
## from PREPROCESSOR_INPUT. Also normalize whitespace.
## Example:
##   $(call remove_enabled_options_crypto,MBEDTLS_FOO MBEDTLS_BAR)
## This expands to an empty string "" if MBEDTLS_FOO and MBEDTLS_BAR are both
## enabled in the TF-PSA-Crypto configuration, to "MBEDTLS_FOO" if
## MBEDTLS_BAR is enabled but MBEDTLS_FOO is disabled, etc.
##
## This only works with a Unix-like shell environment (Bourne/POSIX-style shell
## and standard commands) and a Unix-like compiler (supporting -E). In
## other environments, the output is likely to be empty.
define remove_enabled_options_crypto
$(strip $(shell
  exec 2>/dev/null;
  { echo '#include <tf-psa-crypto/build_info.h>'; echo $(1); } |
  $(CC) $(TF_PSA_CRYPTO_LIBRARY_PUBLIC_INCLUDE) $(CFLAGS) -E - |
  tail -n 1
))
endef

# Ensure that `THREADING` is always defined. This lets us get a clean run
# with `make --warn-undefined-variables` without making the conditionals
# below more complex than they already are. At this stage, if `$(THREADING)`
# is empty, it means we don't know yet whether the threading implementation
# requires extra `LDFLAGS`. Once we've done the analysis, if `$(THREADING)`
# is empty, it will mean that no extra `LDFLAGS` are required, either
# because threading is disabled or because the threading implementation
# doesn't require any extra `LDFLAGS`.
THREADING ?=

ifndef WINDOWS_BUILD
  ifeq ($(THREADING),)
    # Auto-detect configurations with pthread.
    # If the call to remove_enabled_options returns "control", the symbols
    # are confirmed set and we link with pthread.
    # If the auto-detection fails, the result of the call is empty and
    # we keep THREADING undefined.
    ifeq (control,$(call remove_enabled_options_crypto,control MBEDTLS_THREADING_C MBEDTLS_THREADING_PTHREAD))
      THREADING := pthread
    endif
  endif
  #$(info THREADING = $(THREADING))

  ifeq ($(THREADING),pthread)
    LOCAL_LDFLAGS += -lpthread
  endif
endif

TF_PSA_CRYPTO_CORE_PATH = $(TF_PSA_CRYPTO_PATH)/core
TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_PATH = $(TF_PSA_CRYPTO_PATH)/drivers/builtin/src

# List the generated files from crypto that are needed in the build,
# because we don't have the list in a consumable form.
TF_PSA_CRYPTO_LIBRARY_GENERATED_FILES := \
	$(TF_PSA_CRYPTO_CORE_PATH)/psa_crypto_driver_wrappers.h \
	$(TF_PSA_CRYPTO_CORE_PATH)/psa_crypto_driver_wrappers_no_static.c \
	$(TF_PSA_CRYPTO_CORE_PATH)/tf_psa_crypto_config_check_before.h \
	$(TF_PSA_CRYPTO_CORE_PATH)/tf_psa_crypto_config_check_final.h \
	$(TF_PSA_CRYPTO_CORE_PATH)/tf_psa_crypto_config_check_user.h
TF_PSA_CRYPTO_PROGRAMS_GENERATED_FILES := \
	$(TF_PSA_CRYPTO_PATH)/programs/psa/psa_constant_names_generated.c

TF_PSA_CRYPTO_LIBRARY_OBJS := $(patsubst %.c, %.o,$(wildcard $(TF_PSA_CRYPTO_CORE_PATH)/*.c $(TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_PATH)/*.c))
TF_PSA_CRYPTO_LIBRARY_GENERATED_OBJS = $(TF_PSA_CRYPTO_CORE_PATH)/psa_crypto_driver_wrappers_no_static.o
TF_PSA_CRYPTO_LIBRARY_OBJS := $(filter-out $(TF_PSA_CRYPTO_LIBRARY_GENERATED_OBJS),$(TF_PSA_CRYPTO_LIBRARY_OBJS))
TF_PSA_CRYPTO_LIBRARY_OBJS += $(TF_PSA_CRYPTO_LIBRARY_GENERATED_OBJS)
TF_PSA_CRYPTO_LIBRARY_OBJS+=$(THIRDPARTY_CRYPTO_OBJECTS)

GENERATED_WRAPPER_FILES = \
                    $(TF_PSA_CRYPTO_CORE_PATH)/psa_crypto_driver_wrappers.h \
                    $(TF_PSA_CRYPTO_CORE_PATH)/psa_crypto_driver_wrappers_no_static.c
$(GENERATED_WRAPPER_FILES): $(TF_PSA_CRYPTO_PATH)/scripts/generate_driver_wrappers.py
$(GENERATED_WRAPPER_FILES): $(TF_PSA_CRYPTO_PATH)/scripts/data_files/driver_templates/psa_crypto_driver_wrappers.h.jinja
$(GENERATED_WRAPPER_FILES): $(TF_PSA_CRYPTO_PATH)/scripts/data_files/driver_templates/psa_crypto_driver_wrappers_no_static.c.jinja
$(GENERATED_WRAPPER_FILES):
	echo "  Gen   $(GENERATED_WRAPPER_FILES)"
	$(PYTHON) $(TF_PSA_CRYPTO_PATH)/scripts/generate_driver_wrappers.py $(TF_PSA_CRYPTO_CORE_PATH)

$(TF_PSA_CRYPTO_CORE_PATH)/psa_crypto.o:$(TF_PSA_CRYPTO_CORE_PATH)/psa_crypto_driver_wrappers.h

TF_PSA_CRYPTO_GENERATED_CONFIG_CHECK_FILES = $(shell $(PYTHON) \
	$(TF_PSA_CRYPTO_CORE_PATH)/../scripts/generate_config_checks.py \
	--list $(TF_PSA_CRYPTO_CORE_PATH))
$(TF_PSA_CRYPTO_GENERATED_CONFIG_CHECK_FILES): $(gen_file_dep) \
	$(TF_PSA_CRYPTO_CORE_PATH)/../scripts/generate_config_checks.py \
	../framework/scripts/mbedtls_framework/config_checks_generator.py
$(TF_PSA_CRYPTO_GENERATED_CONFIG_CHECK_FILES):
	echo "  Gen   $(TF_PSA_CRYPTO_GENERATED_CONFIG_CHECK_FILES)"
	$(PYTHON) $(TF_PSA_CRYPTO_CORE_PATH)/../scripts/generate_config_checks.py

$(TF_PSA_CRYPTO_CORE_PATH)/tf_psa_crypto_config.o: $(TF_PSA_CRYPTO_GENERATED_CONFIG_CHECK_FILES)

$(TF_PSA_CRYPTO_PATH)/programs/psa/psa_constant_names_generated.c: $(gen_file_dep) $(TF_PSA_CRYPTO_PATH)/scripts/generate_psa_constants.py
$(TF_PSA_CRYPTO_PATH)/programs/psa/psa_constant_names_generated.c: $(gen_file_dep) $(TF_PSA_CRYPTO_PATH)/include/psa/crypto_values.h
$(TF_PSA_CRYPTO_PATH)/programs/psa/psa_constant_names_generated.c: $(gen_file_dep) $(TF_PSA_CRYPTO_PATH)/include/psa/crypto_extra.h
$(TF_PSA_CRYPTO_PATH)/programs/psa/psa_constant_names_generated.c: $(gen_file_dep) $(TF_PSA_CRYPTO_PATH)/tests/suites/test_suite_psa_crypto_metadata.data
$(TF_PSA_CRYPTO_PATH)/programs/psa/psa_constant_names_generated.c:
	echo "  Gen   $@"
	cd $(TF_PSA_CRYPTO_PATH); $(PYTHON) ./scripts/generate_psa_constants.py

GENERATED_BIGNUM_DATA_FILES := $(addprefix $(TF_PSA_CRYPTO_PATH)/,$(shell \
	$(PYTHON) ../framework/scripts/generate_bignum_tests.py --list || \
	echo FAILED \
))
ifeq ($(GENERATED_BIGNUM_DATA_FILES),FAILED)
$(error "$(PYTHON) ../framework/scripts/generate_bignum_tests.py --list" failed)
endif
TF_PSA_CRYPTO_TESTS_GENERATED_DATA_FILES += $(GENERATED_BIGNUM_DATA_FILES)

GENERATED_ECP_DATA_FILES := $(addprefix $(TF_PSA_CRYPTO_PATH)/,$(shell \
	$(PYTHON) ../framework/scripts/generate_ecp_tests.py --list || \
	echo FAILED \
))
ifeq ($(GENERATED_ECP_DATA_FILES),FAILED)
$(error "$(PYTHON) ../framework/scripts/generate_ecp_tests.py --list" failed)
endif
TF_PSA_CRYPTO_TESTS_GENERATED_DATA_FILES += $(GENERATED_ECP_DATA_FILES)

GENERATED_PSA_DATA_FILES := $(addprefix $(TF_PSA_CRYPTO_PATH)/,$(shell \
	$(PYTHON) ../framework/scripts/generate_psa_tests.py --list || \
	echo FAILED \
))
ifeq ($(GENERATED_PSA_DATA_FILES),FAILED)
$(error "$(PYTHON) ../framework/scripts/generate_psa_tests.py --list" failed)
endif
TF_PSA_CRYPTO_TESTS_GENERATED_DATA_FILES += $(GENERATED_PSA_DATA_FILES)

# generate_bignum_tests.py and generate_psa_tests.py spend more time analyzing
# inputs than generating outputs. Its inputs are the same no matter which files
# are being generated.
# It's rare not to want all the outputs. So always generate all of its outputs.
# Use an intermediate phony dependency so that parallel builds don't run
# a separate instance of the recipe for each output file.
$(GENERATED_BIGNUM_DATA_FILES): $(gen_file_dep) generated_bignum_test_data
generated_bignum_test_data: ../framework/scripts/generate_bignum_tests.py
generated_bignum_test_data: ../framework/scripts/mbedtls_framework/bignum_common.py
generated_bignum_test_data: ../framework/scripts/mbedtls_framework/bignum_core.py
generated_bignum_test_data: ../framework/scripts/mbedtls_framework/bignum_mod_raw.py
generated_bignum_test_data: ../framework/scripts/mbedtls_framework/bignum_mod.py
generated_bignum_test_data: ../framework/scripts/mbedtls_framework/test_case.py
generated_bignum_test_data: ../framework/scripts/mbedtls_framework/test_data_generation.py
generated_bignum_test_data:
	echo "  Gen   $(GENERATED_BIGNUM_DATA_FILES)"
	$(PYTHON) ../framework/scripts/generate_bignum_tests.py --directory $(TF_PSA_CRYPTO_PATH)/tests/suites
.SECONDARY: generated_bignum_test_data

$(GENERATED_ECP_DATA_FILES): $(gen_file_dep) generated_ecp_test_data
generated_ecp_test_data: ../framework/scripts/generate_ecp_tests.py
generated_ecp_test_data: ../framework/scripts/mbedtls_framework/bignum_common.py
generated_ecp_test_data: ../framework/scripts/mbedtls_framework/ecp.py
generated_ecp_test_data: ../framework/scripts/mbedtls_framework/test_case.py
generated_ecp_test_data: ../framework/scripts/mbedtls_framework/test_data_generation.py
generated_ecp_test_data:
	echo "  Gen   $(GENERATED_ECP_DATA_FILES)"
	$(PYTHON) ../framework/scripts/generate_ecp_tests.py --directory $(TF_PSA_CRYPTO_PATH)/tests/suites
.SECONDARY: generated_ecp_test_data

$(GENERATED_PSA_DATA_FILES): $(gen_file_dep) generated_psa_test_data
generated_psa_test_data: ../framework/scripts/generate_psa_tests.py
generated_psa_test_data: ../framework/scripts/mbedtls_framework/crypto_data_tests.py
generated_psa_test_data: ../framework/scripts/mbedtls_framework/crypto_knowledge.py
generated_psa_test_data: ../framework/scripts/mbedtls_framework/macro_collector.py
generated_psa_test_data: ../framework/scripts/mbedtls_framework/psa_information.py
generated_psa_test_data: ../framework/scripts/mbedtls_framework/psa_storage.py
generated_psa_test_data: ../framework/scripts/mbedtls_framework/psa_test_case.py
generated_psa_test_data: ../framework/scripts/mbedtls_framework/test_case.py
generated_psa_test_data: ../framework/scripts/mbedtls_framework/test_data_generation.py
## The generated file only depends on the options that are present in
## crypto_config.h, not on which options are set. To avoid regenerating this
## file all the time when switching between configurations, don't declare
## crypto_config.h as a dependency. Remove this file from your working tree
## if you've just added or removed an option in crypto_config.h.
#generated_psa_test_data: $(TF_PSA_CRYPTO_PATH)/include/psa/crypto_config.h
generated_psa_test_data: $(TF_PSA_CRYPTO_PATH)/include/psa/crypto_values.h
generated_psa_test_data: $(TF_PSA_CRYPTO_PATH)/include/psa/crypto_extra.h
generated_psa_test_data: $(TF_PSA_CRYPTO_PATH)/tests/suites/test_suite_psa_crypto_metadata.data
generated_psa_test_data:
	echo "  Gen   $(GENERATED_PSA_DATA_FILES) ..."
	$(PYTHON) ../framework/scripts/generate_psa_tests.py --directory $(TF_PSA_CRYPTO_PATH)/tests/suites
.SECONDARY: generated_psa_test_data

TF_PSA_CRYPTO_APPS := \
	$(TF_PSA_CRYPTO_PATH)/programs/psa/aead_demo \
	$(TF_PSA_CRYPTO_PATH)/programs/psa/crypto_examples \
	$(TF_PSA_CRYPTO_PATH)/programs/psa/hmac_demo \
	$(TF_PSA_CRYPTO_PATH)/programs/psa/key_ladder_demo \
	$(TF_PSA_CRYPTO_PATH)/programs/psa/psa_constant_names \
	$(TF_PSA_CRYPTO_PATH)/programs/psa/psa_hash \
	$(TF_PSA_CRYPTO_PATH)/programs/test/which_aes \
# End of APPS

$(TF_PSA_CRYPTO_PATH)/programs/psa/aead_demo$(EXEXT): $(TF_PSA_CRYPTO_PATH)/programs/psa/aead_demo.c $(DEP)
	echo "  CC    psa/aead_demo.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $(TF_PSA_CRYPTO_PATH)/programs/psa/aead_demo.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

$(TF_PSA_CRYPTO_PATH)/programs/psa/crypto_examples$(EXEXT): $(TF_PSA_CRYPTO_PATH)/programs/psa/crypto_examples.c $(DEP)
	echo "  CC    psa/crypto_examples.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $(TF_PSA_CRYPTO_PATH)/programs/psa/crypto_examples.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

$(TF_PSA_CRYPTO_PATH)/programs/psa/hmac_demo$(EXEXT): $(TF_PSA_CRYPTO_PATH)/programs/psa/hmac_demo.c $(DEP)
	echo "  CC    psa/hmac_demo.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $(TF_PSA_CRYPTO_PATH)/programs/psa/hmac_demo.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

$(TF_PSA_CRYPTO_PATH)/programs/psa/key_ladder_demo$(EXEXT): $(TF_PSA_CRYPTO_PATH)/programs/psa/key_ladder_demo.c $(DEP)
	echo "  CC    psa/key_ladder_demo.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $(TF_PSA_CRYPTO_PATH)/programs/psa/key_ladder_demo.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

$(TF_PSA_CRYPTO_PATH)/programs/psa/psa_constant_names$(EXEXT): $(TF_PSA_CRYPTO_PATH)/programs/psa/psa_constant_names.c $(TF_PSA_CRYPTO_PATH)/programs/psa/psa_constant_names_generated.c $(DEP)
	echo "  CC    psa/psa_constant_names.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $(TF_PSA_CRYPTO_PATH)/programs/psa/psa_constant_names.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

$(TF_PSA_CRYPTO_PATH)/programs/psa/psa_hash$(EXEXT): $(TF_PSA_CRYPTO_PATH)/programs/psa/psa_hash.c $(DEP)
	echo "  CC    psa/psa_hash.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $(TF_PSA_CRYPTO_PATH)/programs/psa/psa_hash.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

$(TF_PSA_CRYPTO_PATH)/programs/test/which_aes$(EXEXT): $(TF_PSA_CRYPTO_PATH)/programs/test/which_aes.c $(DEP)
	echo "  CC    test/which_aes.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $(TF_PSA_CRYPTO_PATH)/programs/test/which_aes.c    $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@
