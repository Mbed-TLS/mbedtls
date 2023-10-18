THIRDPARTY_INCLUDES+=-I../3rdparty/p256-m/p256-m/include -I../3rdparty/p256-m/p256-m/include/p256-m -I../3rdparty/p256-m/p256-m_driver_interface

THIRDPARTY_CRYPTO_OBJECTS+= \
	../3rdparty/p256-m//p256-m_driver_entrypoints.o \
	../3rdparty/p256-m//p256-m/p256-m.o
