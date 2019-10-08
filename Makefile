
DESTDIR=/usr/local
PREFIX=mbedtls_

PROGRAMS_DIR=./programs
TESTS_DIR=./tests

# Check test environment. If ../library is available then Mbed TLS is used.
# Otherwise Mbed OS environment is used.
DIR_FOR_MBED_TLS_ENV=./library
ifneq "$(wildcard $(DIR_FOR_MBED_TLS_ENV) )" ""
	LIBRARY_DIR=./library
	INCLUDE_DIR=./include
	CONFIG_FILE=./include/mbedtls/config.h
else
	LIBRARY_DIR=./src
	INCLUDE_DIR=./inc
	CONFIG_FILE=./inc/mbedtls/test_config.h
endif

.SILENT:

.PHONY: all no_test programs lib tests install uninstall clean test check covtest lcov apidoc apidoc_clean

all: programs tests
	$(MAKE) post_build

no_test: programs

programs: lib
	$(MAKE) -C $(PROGRAMS_DIR)

lib:
	$(MAKE) -C $(LIBRARY_DIR)

tests: lib
	$(MAKE) -C $(TESTS_DIR)

ifndef WINDOWS
install: no_test
	mkdir -p $(DESTDIR)/$(INCLUDE_DIR)/mbedtls
	cp -rp $(INCLUDE_DIR)/mbedtls $(DESTDIR)/$(INCLUDE_DIR)

	mkdir -p $(DESTDIR)/lib
	cp -RP $(LIBRARY_DIR)/libmbedtls.*    $(DESTDIR)/lib
	cp -RP $(LIBRARY_DIR)/libmbedx509.*   $(DESTDIR)/lib
	cp -RP $(LIBRARY_DIR)/libmbedcrypto.* $(DESTDIR)/lib

	mkdir -p $(DESTDIR)/bin
	for p in $(PROGRAMS_DIR)/*/* ; do              \
	    if [ -x $$p ] && [ ! -d $$p ] ;     \
	    then                                \
	        f=$(PREFIX)`basename $$p` ;     \
	        cp $$p $(DESTDIR)/bin/$$f ;     \
	    fi                                  \
	done

uninstall:
	rm -rf $(DESTDIR)/$(INCLUDE_DIR)/mbedtls
	rm -f $(DESTDIR)/lib/libmbedtls.*
	rm -f $(DESTDIR)/lib/libmbedx509.*
	rm -f $(DESTDIR)/lib/libmbedcrypto.*

	for p in $(PROGRAMS_DIR)/*/* ; do              \
	    if [ -x $$p ] && [ ! -d $$p ] ;     \
	    then                                \
	        f=$(PREFIX)`basename $$p` ;     \
	        rm -f $(DESTDIR)/bin/$$f ;      \
	    fi                                  \
	done
endif

WARNING_BORDER      =*******************************************************\n
NULL_ENTROPY_WARN_L1=****  WARNING!  MBEDTLS_TEST_NULL_ENTROPY defined! ****\n
NULL_ENTROPY_WARN_L2=****  THIS BUILD HAS NO DEFINED ENTROPY SOURCES    ****\n
NULL_ENTROPY_WARN_L3=****  AND IS *NOT* SUITABLE FOR PRODUCTION USE     ****\n

NULL_ENTROPY_WARNING=\n$(WARNING_BORDER)$(NULL_ENTROPY_WARN_L1)$(NULL_ENTROPY_WARN_L2)$(NULL_ENTROPY_WARN_L3)$(WARNING_BORDER)

WARNING_BORDER_LONG      =**********************************************************************************\n
CTR_DRBG_128_BIT_KEY_WARN_L1=****  WARNING!  MBEDTLS_CTR_DRBG_USE_128_BIT_KEY defined!                      ****\n
CTR_DRBG_128_BIT_KEY_WARN_L2=****  Using 128-bit keys for CTR_DRBG limits the security of generated         ****\n
CTR_DRBG_128_BIT_KEY_WARN_L3=****  keys and operations that use random values generated to 128-bit security ****\n

CTR_DRBG_128_BIT_KEY_WARNING=\n$(WARNING_BORDER_LONG)$(CTR_DRBG_128_BIT_KEY_WARN_L1)$(CTR_DRBG_128_BIT_KEY_WARN_L2)$(CTR_DRBG_128_BIT_KEY_WARN_L3)$(WARNING_BORDER_LONG)

# Post build steps
post_build:
ifndef WINDOWS

	# If 128-bit keys are configured for CTR_DRBG, display an appropriate warning
	-scripts/config.pl -f $(CONFIG_FILE) get MBEDTLS_CTR_DRBG_USE_128_BIT_KEY && ([ $$? -eq 0 ]) && \
	    echo '$(CTR_DRBG_128_BIT_KEY_WARNING)'

	# If NULL Entropy is configured, display an appropriate warning
	-scripts/config.pl -f $(CONFIG_FILE) get MBEDTLS_TEST_NULL_ENTROPY && ([ $$? -eq 0 ]) && \
	    echo '$(NULL_ENTROPY_WARNING)'
endif

clean:
	$(MAKE) -C $(LIBRARY_DIR) clean
	$(MAKE) -C $(PROGRAMS_DIR) clean
	$(MAKE) -C $(TESTS_DIR) clean
ifndef WINDOWS
	find . \( -name \*.gcno -o -name \*.gcda -o -name \*.info \) -exec rm {} +
endif

check: lib tests
	$(MAKE) -C $(TESTS_DIR) check

test: check

ifndef WINDOWS
# note: for coverage testing, build with:
# make CFLAGS='--coverage -g3 -O0'
covtest:
	$(MAKE) check
	$(PROGRAMS_DIR)/test/selftest
	$(TESTS_DIR)/compat.sh
	$(TESTS_DIR)/ssl-opt.sh

lcov:
	rm -rf Coverage
	lcov --capture --initial --directory $(LIBRARY_DIR) -o files.info
	lcov --capture --directory $(LIBRARY_DIR) -o tests.info
	lcov --add-tracefile files.info --add-tracefile tests.info -o all.info
	lcov --remove all.info -o final.info '*.h'
	gendesc tests/Descriptions.txt -o descriptions
	genhtml --title "mbed TLS" --description-file descriptions --keep-descriptions --legend --no-branch-coverage -o Coverage final.info
	rm -f files.info tests.info all.info final.info descriptions

apidoc:
	mkdir -p apidoc
	cd doxygen && doxygen mbedtls.doxyfile

apidoc_clean:
	rm -rf apidoc
endif

## Editor navigation files
C_SOURCE_FILES = $(wildcard $(INCLUDE_DIR)/*/*.h $(LIBRARY_DIR)/*.[hc] $(PROGRAMS_DIR)/*/*.[hc] $(TESTS_DIR)/suites/*.function)
tags: $(C_SOURCE_FILES)
	ctags -o $@ $(C_SOURCE_FILES)
TAGS: $(C_SOURCE_FILES)
	etags -o $@ $(C_SOURCE_FILES)
GPATH GRTAGS GSYMS GTAGS: $(C_SOURCE_FILES)
	ls $(C_SOURCE_FILES) | gtags -f - --gtagsconf .globalrc
