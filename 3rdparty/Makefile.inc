THIRDPARTY_DIR = $(dir $(lastword $(MAKEFILE_LIST)))
include $(THIRDPARTY_DIR)/everest/Makefile.inc
include ../3rdparty/p256-m/Makefile.inc
