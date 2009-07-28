
DESTDIR=/usr/local
PREFIX=polarssl_

.SILENT:

all:
	cd library  && make all && cd ..
	cd programs && make all && cd ..
	cd tests && make all && cd ..

install:
	mkdir -p $(DESTDIR)/include/polarssl
	cp -r include/polarssl $(DESTDIR)/include
	
	mkdir -p $(DESTDIR)/lib
	cp library/libpolarssl.* $(DESTDIR)/lib
	
	mkdir -p $(DESTDIR)/bin
	for p in programs/*/* ; do              \
	    if [ -x $$p ] && [ ! -d $$p ] ;     \
	    then                                \
	        f=$(PREFIX)`basename $$p` ;     \
	        cp $$p $(DESTDIR)/bin/$$f ;     \
	    fi                                  \
	done

clean:
	cd library  && make clean && cd ..
	cd programs && make clean && cd ..
	cd tests && make clean && cd ..

check:
	( cd tests && make check )
