#include "common.h"
int __psa_ff_client_security_state = NON_SECURE;

#if 0
static void _printbits(uint32_t num) {
    for (int i=0; i<32; i++) {
        if ((num >> (31-i) & 0x1)) {
            INFO("1");
        } else {
            INFO("0");
        }
    }
    INFO("\n");
}
#endif
