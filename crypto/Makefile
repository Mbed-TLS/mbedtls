.PHONY: all lib programs tests clean test

all: programs tests

lib:
	$(MAKE) -C library

programs: lib
	$(MAKE) -C programs

tests: lib
	$(MAKE) -C tests

clean:
	$(MAKE) -C library clean
	$(MAKE) -C programs clean
	$(MAKE) -C tests clean

test: lib tests
	$(MAKE) -C tests test
