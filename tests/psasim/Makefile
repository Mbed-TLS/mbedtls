CFLAGS ?=  -Wall -std=c99
INCLUDE := -I./include/
DESTDIR ?= /usr/local
PREFIX := libpsaff
BUILDDIR ?= bin

.PHONY: all install test uninstall run docker ci

all: libpsaff.so

libpsaff.so:
	$(CC) $(INCLUDE) $(CFLAGS) -c -fpic src/common.c -o common.o
	$(CC) $(INCLUDE) $(CFLAGS) -c -fpic src/client.c -o client.o
	$(CC) $(INCLUDE) $(CFLAGS) -c -fpic src/service.c -o server.o
	$(CC) -shared -o libpsaff.so common.o client.o server.o

ifeq ($(DEBUG),1)
  CFLAGS += -DDEBUG -g
endif

clean:
	rm -rf $(BUILDDIR)
	rm -f *.so *.o
	rm -rf test/*dSYM
	cd test && make clean

test:
	cd test && make

test/partition:
	cd test && make

run: test/partition
	pkill partition || true
	pkill client || true
	ipcs | grep q | awk '{ printf " -q " $$2 }' | xargs ipcrm > /dev/null 2>&1 || true
	(sleep 3 && ./test/client)&
	./test/partition

ci:
	pkill client || true
	ipcs | grep q | awk '{ printf " -q " $$2 }' | xargs ipcrm > /dev/null 2>&1 || true
	./test/partition 2>&1  &
	sleep 3 && ./test/client
	pkill partition || true

docker:
	@docker run --rm -ti -v $$PWD:/opt --entrypoint /bin/bash ubuntu \
		-c "cd /opt && ls && apt-get update -qq && apt install \
		-y gcc make gdb python -qq && make clean && make install && make test && ldconfig && make run"

install: libpsaff.so
	mkdir -p $(DESTDIR)/lib
	mkdir -p $(DESTDIR)/include
	cp libpsaff.so $(DESTDIR)/lib/
	cp -r include/* $(DESTDIR)/include/
	cp tools/psa_autogen /usr/local/bin/

uninstall:
	rm $(DESTDIR)/lib/libpsaff.so
	rm -rf $(DESTDIR)/include/psa
	rm -rf $(DESTDIR)/include/psasim
	rm -f /usr/local/bin/psa_autogen

