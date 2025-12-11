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
