THIRDPARTY_DIR = $(dir $(word 2, $(MAKEFILE_LIST)))
include $(THIRDPARTY_DIR)/everest/Makefile.inc
include $(THIRDPARTY_DIR)/p256-m/Makefile.inc
