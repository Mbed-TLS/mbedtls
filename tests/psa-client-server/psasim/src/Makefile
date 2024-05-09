# Here I'm picking also libpsaclient/include because I just need it for the
# psa/crypto.h include. libpsaserver would have worked the same.
INCLUDE = -I../include/ -I../../../libpsaclient/include
PSA_LIB = libpsaff.a

PSA_LIB_OBJS = client.o service.o

.PHONY: all lib

all: $(PSA_LIB)

%.o: %.c
	$(CC) $(INCLUDE) $(CFLAGS) -c $< -o $@

$(PSA_LIB): $(PSA_LIB_OBJS)
	$(AR) rcs $(PSA_LIB) client.o service.o

clean:
	rm -f $(PSA_LIB) $(PSA_LIB_OBJS)
