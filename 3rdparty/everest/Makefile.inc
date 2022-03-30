THIRDPARTY_INCLUDES+=$(patsubst %,-I$(abspath $(THIRDPARTY_DIR))/%,everest/include everest/include/everest everest/include/everest/kremlib)

THIRDPARTY_CRYPTO_OBJECTS+= \
	$(THIRDPARTY_DIR)everest/library/everest.o \
	$(THIRDPARTY_DIR)everest/library/x25519.o \
	$(THIRDPARTY_DIR)everest/library/Hacl_Curve25519_joined.o
