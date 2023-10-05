#include <stdint.h>
#include <psa/service.h>
void raise_signal(psa_signal_t signal);
void __init_psasim(const char **array,
                   int size,
		   const int allow_ns_clients_array[32],
                   const uint32_t versions[32],
                 const int strict_policy_array[32]);
