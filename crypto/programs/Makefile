CFLAGS ?= -O2 -I../include
WARNING_CFLAGS ?= \
	-Werror -Wall -Wextra \
	-Wno-unused-function \
	-Wno-overlength-strings \
	-Wdeclaration-after-statement \
# Don't delete this line.

LDFLAGS ?= -L../library -lmbedcrypto

DEP := ../library/libmbedcrypto.a

APPS := \
	psa/crypto_examples \
	psa/key_ladder_demo \
	psa/psa_constant_names \
# Don't delete this line.

EXTRA_GENERATED := \
	psa/psa_constant_names_generated.c \
# Don't delete this line.

.SILENT:

.PHONY: all clean list

all: $(APPS)

$(DEP):
	$(MAKE) -C ../library

psa/crypto_examples: psa/crypto_examples.c $(DEP)
	echo "  CC    psa/crypto_examples.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) psa/crypto_examples.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

psa/key_ladder_demo: psa/key_ladder_demo.c $(DEP)
	echo "  CC    psa/key_ladder_demo.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) psa/key_ladder_demo.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

psa/psa_constant_names_generated.c: ../scripts/generate_psa_constants.py ../include/psa/crypto.h
	../scripts/generate_psa_constants.py

psa/psa_constant_names: psa/psa_constant_names_generated.c psa/psa_constant_names.c $(DEP)
	echo "  CC    psa/psa_constant_names.c"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) psa/psa_constant_names.c $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

clean:
	rm -f $(APPS) $(EXTRA_GENERATED)

list:
	echo $(APPS)
