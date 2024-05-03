CFLAGS ?= -Wall -Werror -std=c99 -D_XOPEN_SOURCE=1 -D_POSIX_C_SOURCE=200809L

ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG -O0 -g
endif

.PHONY: all lib test run

all: lib test

lib:
	$(MAKE) -C src CFLAGS="$(CFLAGS)"

test: lib
	$(MAKE) -C test CFLAGS="$(CFLAGS)"

clean:
	rm -f $(PSA_LIB) $(PSA_LIB_OBJS)
	$(MAKE) -C test clean
	$(MAKE) -C src clean

run: test
	cd test && ./run_test.sh
