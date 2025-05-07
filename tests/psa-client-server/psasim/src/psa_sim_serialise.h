/**
 * \file psa_sim_serialise.h
 *
 * \brief Rough-and-ready serialisation and deserialisation for the PSA Crypto simulator
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <stdint.h>
#include <stddef.h>

#include "psa/crypto.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"

/* Basic idea:
 *
 * All arguments to a function will be serialised into a single buffer to
 * be sent to the server with the PSA crypto function to be called.
 *
 * All returned data (the function's return value and any values returned
 * via `out` parameters) will similarly be serialised into a buffer to be
 * sent back to the client from the server.
 *
 * For each data type foo (e.g. int, size_t, psa_algorithm_t, but also "buffer"
 * where "buffer" is a (uint8_t *, size_t) pair, we have a pair of functions,
 * psasim_serialise_foo() and psasim_deserialise_foo().
 *
 * We also have psasim_serialise_foo_needs() functions, which return a
 * size_t giving the number of bytes that serialising that instance of that
 * type will need. This allows callers to size buffers for serialisation.
 *
 * Each serialised buffer starts with a version byte, bytes that indicate
 * the size of basic C types, and four bytes that indicate the endianness
 * (to avoid incompatibilities if we ever run this over a network - we are
 * not aiming for universality, just for correctness and simplicity).
 *
 * Most types are serialised as a fixed-size (per type) octet string, with
 * no type indication. This is acceptable as (a) this is for the test PSA crypto
 * simulator only, not production, and (b) these functions are called by
 * code that itself is written by script.
 *
 * We also want to keep serialised data reasonably compact as communication
 * between client and server goes in messages of less than 200 bytes each.
 *
 * Many serialisation functions can be created by a script; an exemplar Perl
 * script is included. It is not hooked into the build and so must be run
 * manually, but is expected to be replaced by a Python script in due course.
 * Types that can have their functions created by script include plain old C
 * data types (e.g. int), types typedef'd to those, and even structures that
 * don't contain pointers.
 */

/** Reset all operation slots.
 *
 * Should be called when all clients have disconnected.
 */
void psa_sim_serialize_reset(void);

/** Return how much buffer space is needed by \c psasim_serialise_begin().
 *
 * \return                   The number of bytes needed in the buffer for
 *                           \c psasim_serialise_begin()'s output.
 */
size_t psasim_serialise_begin_needs(void);

/** Begin serialisation into a buffer.
 *
 *                           This must be the first serialisation API called
 *                           on a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error (likely
 *                           no space).
 */
int psasim_serialise_begin(uint8_t **pos, size_t *remaining);

/** Begin deserialisation of a buffer.
 *
 *                           This must be the first deserialisation API called
 *                           on a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_begin(uint8_t **pos, size_t *remaining);

/** Return how much buffer space is needed by \c psasim_serialise_unsigned_int()
 *  to serialise an `unsigned int`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_unsigned_int() to serialise
 *                           the given value.
 */
size_t psasim_serialise_unsigned_int_needs(
    unsigned int value);

/** Serialise an `unsigned int` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_unsigned_int(uint8_t **pos,
                                  size_t *remaining,
                                  unsigned int value);

/** Deserialise an `unsigned int` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to an `unsigned int` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_unsigned_int(uint8_t **pos,
                                    size_t *remaining,
                                    unsigned int *value);

/** Return how much buffer space is needed by \c psasim_serialise_int()
 *  to serialise an `int`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_int() to serialise
 *                           the given value.
 */
size_t psasim_serialise_int_needs(
    int value);

/** Serialise an `int` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_int(uint8_t **pos,
                         size_t *remaining,
                         int value);

/** Deserialise an `int` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to an `int` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_int(uint8_t **pos,
                           size_t *remaining,
                           int *value);

/** Return how much buffer space is needed by \c psasim_serialise_size_t()
 *  to serialise a `size_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_size_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_size_t_needs(
    size_t value);

/** Serialise a `size_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_size_t(uint8_t **pos,
                            size_t *remaining,
                            size_t value);

/** Deserialise a `size_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `size_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_size_t(uint8_t **pos,
                              size_t *remaining,
                              size_t *value);

/** Return how much buffer space is needed by \c psasim_serialise_uint16_t()
 *  to serialise an `uint16_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_uint16_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_uint16_t_needs(
    uint16_t value);

/** Serialise an `uint16_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_uint16_t(uint8_t **pos,
                              size_t *remaining,
                              uint16_t value);

/** Deserialise an `uint16_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to an `uint16_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_uint16_t(uint8_t **pos,
                                size_t *remaining,
                                uint16_t *value);

/** Return how much buffer space is needed by \c psasim_serialise_uint32_t()
 *  to serialise an `uint32_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_uint32_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_uint32_t_needs(
    uint32_t value);

/** Serialise an `uint32_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_uint32_t(uint8_t **pos,
                              size_t *remaining,
                              uint32_t value);

/** Deserialise an `uint32_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to an `uint32_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_uint32_t(uint8_t **pos,
                                size_t *remaining,
                                uint32_t *value);

/** Return how much buffer space is needed by \c psasim_serialise_uint64_t()
 *  to serialise an `uint64_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_uint64_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_uint64_t_needs(
    uint64_t value);

/** Serialise an `uint64_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_uint64_t(uint8_t **pos,
                              size_t *remaining,
                              uint64_t value);

/** Deserialise an `uint64_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to an `uint64_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_uint64_t(uint8_t **pos,
                                size_t *remaining,
                                uint64_t *value);

/** Return how much space is needed by \c psasim_serialise_buffer()
 *  to serialise a buffer: a (`uint8_t *`, `size_t`) pair.
 *
 * \param buffer             Pointer to the buffer to be serialised
 *                           (needed in case some serialisations are value-
 *                           dependent).
 * \param buffer_size        Number of bytes in the buffer to be serialised.
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_buffer() to serialise
 *                           the specified buffer.
 */
size_t psasim_serialise_buffer_needs(const uint8_t *buffer, size_t buffer_size);

/** Serialise a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param buffer             Pointer to the buffer to be serialised.
 * \param buffer_length      Number of bytes in the buffer to be serialised.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_buffer(uint8_t **pos, size_t *remaining,
                            const uint8_t *buffer, size_t buffer_length);

/** Deserialise a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the serialisation buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the serialisation buffer.
 * \param buffer             Pointer to a `uint8_t *` to receive the address
 *                           of a newly-allocated buffer, which the caller
 *                           must `free()`.
 * \param buffer_length      Pointer to a `size_t` to receive the number of
 *                           bytes in the deserialised buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_buffer(uint8_t **pos, size_t *remaining,
                              uint8_t **buffer, size_t *buffer_length);

/** Deserialise a buffer returned from the server.
 *
 * When the client is deserialising a buffer returned from the server, it needs
 * to use this function to deserialised the  returned buffer. It should use the
 * usual \c psasim_serialise_buffer() function to serialise the outbound
 * buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the serialisation buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the serialisation buffer.
 * \param buffer             Pointer to a `uint8_t *` to receive the address
 *                           of a newly-allocated buffer, which the caller
 *                           must `free()`.
 * \param buffer_length      Pointer to a `size_t` to receive the number of
 *                           bytes in the deserialised buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_return_buffer(uint8_t **pos, size_t *remaining,
                                     uint8_t *buffer, size_t buffer_length);

/** Return how much buffer space is needed by \c psasim_serialise_psa_custom_key_parameters_t()
 *  to serialise a `psa_custom_key_parameters_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_custom_key_parameters_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_custom_key_parameters_t_needs(
    psa_custom_key_parameters_t value);

/** Serialise a `psa_custom_key_parameters_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_custom_key_parameters_t(uint8_t **pos,
                                                 size_t *remaining,
                                                 psa_custom_key_parameters_t value);

/** Deserialise a `psa_custom_key_parameters_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_custom_key_parameters_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_custom_key_parameters_t(uint8_t **pos,
                                                   size_t *remaining,
                                                   psa_custom_key_parameters_t *value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_status_t()
 *  to serialise a `psa_status_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_status_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_status_t_needs(
    psa_status_t value);

/** Serialise a `psa_status_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_status_t(uint8_t **pos,
                                  size_t *remaining,
                                  psa_status_t value);

/** Deserialise a `psa_status_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_status_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_status_t(uint8_t **pos,
                                    size_t *remaining,
                                    psa_status_t *value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_algorithm_t()
 *  to serialise a `psa_algorithm_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_algorithm_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_algorithm_t_needs(
    psa_algorithm_t value);

/** Serialise a `psa_algorithm_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_algorithm_t(uint8_t **pos,
                                     size_t *remaining,
                                     psa_algorithm_t value);

/** Deserialise a `psa_algorithm_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_algorithm_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_algorithm_t(uint8_t **pos,
                                       size_t *remaining,
                                       psa_algorithm_t *value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_key_derivation_step_t()
 *  to serialise a `psa_key_derivation_step_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_key_derivation_step_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_key_derivation_step_t_needs(
    psa_key_derivation_step_t value);

/** Serialise a `psa_key_derivation_step_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_key_derivation_step_t(uint8_t **pos,
                                               size_t *remaining,
                                               psa_key_derivation_step_t value);

/** Deserialise a `psa_key_derivation_step_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_key_derivation_step_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_key_derivation_step_t(uint8_t **pos,
                                                 size_t *remaining,
                                                 psa_key_derivation_step_t *value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_hash_operation_t()
 *  to serialise a `psa_hash_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_hash_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_hash_operation_t_needs(
    psa_hash_operation_t value);

/** Serialise a `psa_hash_operation_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_hash_operation_t(uint8_t **pos,
                                          size_t *remaining,
                                          psa_hash_operation_t value);

/** Deserialise a `psa_hash_operation_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_hash_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_hash_operation_t(uint8_t **pos,
                                            size_t *remaining,
                                            psa_hash_operation_t *value);

/** Return how much buffer space is needed by \c psasim_server_serialise_psa_hash_operation_t()
 *  to serialise a `psa_hash_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_hash_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_server_serialise_psa_hash_operation_t_needs(
    psa_hash_operation_t *value);

/** Serialise a `psa_hash_operation_t` into a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 * \param completed          Non-zero if the operation is now completed (set by
 *                           finish and abort calls).
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_serialise_psa_hash_operation_t(uint8_t **pos,
                                                 size_t *remaining,
                                                 psa_hash_operation_t *value,
                                                 int completed);

/** Deserialise a `psa_hash_operation_t` from a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_hash_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_deserialise_psa_hash_operation_t(uint8_t **pos,
                                                   size_t *remaining,
                                                   psa_hash_operation_t **value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_aead_operation_t()
 *  to serialise a `psa_aead_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_aead_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_aead_operation_t_needs(
    psa_aead_operation_t value);

/** Serialise a `psa_aead_operation_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_aead_operation_t(uint8_t **pos,
                                          size_t *remaining,
                                          psa_aead_operation_t value);

/** Deserialise a `psa_aead_operation_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_aead_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_aead_operation_t(uint8_t **pos,
                                            size_t *remaining,
                                            psa_aead_operation_t *value);

/** Return how much buffer space is needed by \c psasim_server_serialise_psa_aead_operation_t()
 *  to serialise a `psa_aead_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_aead_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_server_serialise_psa_aead_operation_t_needs(
    psa_aead_operation_t *value);

/** Serialise a `psa_aead_operation_t` into a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 * \param completed          Non-zero if the operation is now completed (set by
 *                           finish and abort calls).
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_serialise_psa_aead_operation_t(uint8_t **pos,
                                                 size_t *remaining,
                                                 psa_aead_operation_t *value,
                                                 int completed);

/** Deserialise a `psa_aead_operation_t` from a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_aead_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_deserialise_psa_aead_operation_t(uint8_t **pos,
                                                   size_t *remaining,
                                                   psa_aead_operation_t **value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_key_attributes_t()
 *  to serialise a `psa_key_attributes_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_key_attributes_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_key_attributes_t_needs(
    psa_key_attributes_t value);

/** Serialise a `psa_key_attributes_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_key_attributes_t(uint8_t **pos,
                                          size_t *remaining,
                                          psa_key_attributes_t value);

/** Deserialise a `psa_key_attributes_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_key_attributes_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_key_attributes_t(uint8_t **pos,
                                            size_t *remaining,
                                            psa_key_attributes_t *value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_mac_operation_t()
 *  to serialise a `psa_mac_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_mac_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_mac_operation_t_needs(
    psa_mac_operation_t value);

/** Serialise a `psa_mac_operation_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_mac_operation_t(uint8_t **pos,
                                         size_t *remaining,
                                         psa_mac_operation_t value);

/** Deserialise a `psa_mac_operation_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_mac_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_mac_operation_t(uint8_t **pos,
                                           size_t *remaining,
                                           psa_mac_operation_t *value);

/** Return how much buffer space is needed by \c psasim_server_serialise_psa_mac_operation_t()
 *  to serialise a `psa_mac_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_mac_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_server_serialise_psa_mac_operation_t_needs(
    psa_mac_operation_t *value);

/** Serialise a `psa_mac_operation_t` into a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 * \param completed          Non-zero if the operation is now completed (set by
 *                           finish and abort calls).
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_serialise_psa_mac_operation_t(uint8_t **pos,
                                                size_t *remaining,
                                                psa_mac_operation_t *value,
                                                int completed);

/** Deserialise a `psa_mac_operation_t` from a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_mac_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_deserialise_psa_mac_operation_t(uint8_t **pos,
                                                  size_t *remaining,
                                                  psa_mac_operation_t **value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_cipher_operation_t()
 *  to serialise a `psa_cipher_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_cipher_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_cipher_operation_t_needs(
    psa_cipher_operation_t value);

/** Serialise a `psa_cipher_operation_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_cipher_operation_t(uint8_t **pos,
                                            size_t *remaining,
                                            psa_cipher_operation_t value);

/** Deserialise a `psa_cipher_operation_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_cipher_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_cipher_operation_t(uint8_t **pos,
                                              size_t *remaining,
                                              psa_cipher_operation_t *value);

/** Return how much buffer space is needed by \c psasim_server_serialise_psa_cipher_operation_t()
 *  to serialise a `psa_cipher_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_cipher_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_server_serialise_psa_cipher_operation_t_needs(
    psa_cipher_operation_t *value);

/** Serialise a `psa_cipher_operation_t` into a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 * \param completed          Non-zero if the operation is now completed (set by
 *                           finish and abort calls).
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_serialise_psa_cipher_operation_t(uint8_t **pos,
                                                   size_t *remaining,
                                                   psa_cipher_operation_t *value,
                                                   int completed);

/** Deserialise a `psa_cipher_operation_t` from a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_cipher_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_deserialise_psa_cipher_operation_t(uint8_t **pos,
                                                     size_t *remaining,
                                                     psa_cipher_operation_t **value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_key_derivation_operation_t()
 *  to serialise a `psa_key_derivation_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_key_derivation_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_key_derivation_operation_t_needs(
    psa_key_derivation_operation_t value);

/** Serialise a `psa_key_derivation_operation_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_key_derivation_operation_t(uint8_t **pos,
                                                    size_t *remaining,
                                                    psa_key_derivation_operation_t value);

/** Deserialise a `psa_key_derivation_operation_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_key_derivation_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_key_derivation_operation_t(uint8_t **pos,
                                                      size_t *remaining,
                                                      psa_key_derivation_operation_t *value);

/** Return how much buffer space is needed by \c psasim_server_serialise_psa_key_derivation_operation_t()
 *  to serialise a `psa_key_derivation_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_key_derivation_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_server_serialise_psa_key_derivation_operation_t_needs(
    psa_key_derivation_operation_t *value);

/** Serialise a `psa_key_derivation_operation_t` into a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 * \param completed          Non-zero if the operation is now completed (set by
 *                           finish and abort calls).
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_serialise_psa_key_derivation_operation_t(uint8_t **pos,
                                                           size_t *remaining,
                                                           psa_key_derivation_operation_t *value,
                                                           int completed);

/** Deserialise a `psa_key_derivation_operation_t` from a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_key_derivation_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_deserialise_psa_key_derivation_operation_t(uint8_t **pos,
                                                             size_t *remaining,
                                                             psa_key_derivation_operation_t **value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_sign_hash_interruptible_operation_t()
 *  to serialise a `psa_sign_hash_interruptible_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_sign_hash_interruptible_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_sign_hash_interruptible_operation_t_needs(
    psa_sign_hash_interruptible_operation_t value);

/** Serialise a `psa_sign_hash_interruptible_operation_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_sign_hash_interruptible_operation_t(uint8_t **pos,
                                                             size_t *remaining,
                                                             psa_sign_hash_interruptible_operation_t value);

/** Deserialise a `psa_sign_hash_interruptible_operation_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_sign_hash_interruptible_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_sign_hash_interruptible_operation_t(uint8_t **pos,
                                                               size_t *remaining,
                                                               psa_sign_hash_interruptible_operation_t *value);

/** Return how much buffer space is needed by \c psasim_server_serialise_psa_sign_hash_interruptible_operation_t()
 *  to serialise a `psa_sign_hash_interruptible_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_sign_hash_interruptible_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_server_serialise_psa_sign_hash_interruptible_operation_t_needs(
    psa_sign_hash_interruptible_operation_t *value);

/** Serialise a `psa_sign_hash_interruptible_operation_t` into a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 * \param completed          Non-zero if the operation is now completed (set by
 *                           finish and abort calls).
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_serialise_psa_sign_hash_interruptible_operation_t(uint8_t **pos,
                                                                    size_t *remaining,
                                                                    psa_sign_hash_interruptible_operation_t *value,
                                                                    int completed);

/** Deserialise a `psa_sign_hash_interruptible_operation_t` from a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_sign_hash_interruptible_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_deserialise_psa_sign_hash_interruptible_operation_t(uint8_t **pos,
                                                                      size_t *remaining,
                                                                      psa_sign_hash_interruptible_operation_t **value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_verify_hash_interruptible_operation_t()
 *  to serialise a `psa_verify_hash_interruptible_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_verify_hash_interruptible_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_verify_hash_interruptible_operation_t_needs(
    psa_verify_hash_interruptible_operation_t value);

/** Serialise a `psa_verify_hash_interruptible_operation_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_verify_hash_interruptible_operation_t(uint8_t **pos,
                                                               size_t *remaining,
                                                               psa_verify_hash_interruptible_operation_t value);

/** Deserialise a `psa_verify_hash_interruptible_operation_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_verify_hash_interruptible_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_verify_hash_interruptible_operation_t(uint8_t **pos,
                                                                 size_t *remaining,
                                                                 psa_verify_hash_interruptible_operation_t *value);

/** Return how much buffer space is needed by \c psasim_server_serialise_psa_verify_hash_interruptible_operation_t()
 *  to serialise a `psa_verify_hash_interruptible_operation_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_verify_hash_interruptible_operation_t() to serialise
 *                           the given value.
 */
size_t psasim_server_serialise_psa_verify_hash_interruptible_operation_t_needs(
    psa_verify_hash_interruptible_operation_t *value);

/** Serialise a `psa_verify_hash_interruptible_operation_t` into a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 * \param completed          Non-zero if the operation is now completed (set by
 *                           finish and abort calls).
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_serialise_psa_verify_hash_interruptible_operation_t(uint8_t **pos,
                                                                      size_t *remaining,
                                                                      psa_verify_hash_interruptible_operation_t *value,
                                                                      int completed);

/** Deserialise a `psa_verify_hash_interruptible_operation_t` from a buffer on the server side.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_verify_hash_interruptible_operation_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_server_deserialise_psa_verify_hash_interruptible_operation_t(uint8_t **pos,
                                                                        size_t *remaining,
                                                                        psa_verify_hash_interruptible_operation_t **value);

/** Return how much buffer space is needed by \c psasim_serialise_mbedtls_svc_key_id_t()
 *  to serialise a `mbedtls_svc_key_id_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_mbedtls_svc_key_id_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_mbedtls_svc_key_id_t_needs(
    mbedtls_svc_key_id_t value);

/** Serialise a `mbedtls_svc_key_id_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_mbedtls_svc_key_id_t(uint8_t **pos,
                                          size_t *remaining,
                                          mbedtls_svc_key_id_t value);

/** Deserialise a `mbedtls_svc_key_id_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `mbedtls_svc_key_id_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_mbedtls_svc_key_id_t(uint8_t **pos,
                                            size_t *remaining,
                                            mbedtls_svc_key_id_t *value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_key_agreement_iop_t()
 *  to serialise a `psa_key_agreement_iop_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_key_agreement_iop_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_key_agreement_iop_t_needs(
    psa_key_agreement_iop_t value);

/** Serialise a `psa_key_agreement_iop_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_key_agreement_iop_t(uint8_t **pos,
                                             size_t *remaining,
                                             psa_key_agreement_iop_t value);

/** Deserialise a `psa_key_agreement_iop_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_key_agreement_iop_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_key_agreement_iop_t(uint8_t **pos,
                                               size_t *remaining,
                                               psa_key_agreement_iop_t *value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_generate_key_iop_t()
 *  to serialise a `psa_generate_key_iop_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_generate_key_iop_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_generate_key_iop_t_needs(
    psa_generate_key_iop_t value);

/** Serialise a `psa_generate_key_iop_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_generate_key_iop_t(uint8_t **pos,
                                            size_t *remaining,
                                            psa_generate_key_iop_t value);

/** Deserialise a `psa_generate_key_iop_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_generate_key_iop_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_generate_key_iop_t(uint8_t **pos,
                                              size_t *remaining,
                                              psa_generate_key_iop_t *value);

/** Return how much buffer space is needed by \c psasim_serialise_psa_export_public_key_iop_t()
 *  to serialise a `psa_export_public_key_iop_t`.
 *
 * \param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \return                   The number of bytes needed in the buffer by
 *                           \c psasim_serialise_psa_export_public_key_iop_t() to serialise
 *                           the given value.
 */
size_t psasim_serialise_psa_export_public_key_iop_t_needs(
    psa_export_public_key_iop_t value);

/** Serialise a `psa_export_public_key_iop_t` into a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              The value to serialise into the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_serialise_psa_export_public_key_iop_t(uint8_t **pos,
                                                 size_t *remaining,
                                                 psa_export_public_key_iop_t value);

/** Deserialise a `psa_export_public_key_iop_t` from a buffer.
 *
 * \param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \param value              Pointer to a `psa_export_public_key_iop_t` to receive the value
 *                           deserialised from the buffer.
 *
 * \return                   \c 1 on success ("okay"), \c 0 on error.
 */
int psasim_deserialise_psa_export_public_key_iop_t(uint8_t **pos,
                                                   size_t *remaining,
                                                   psa_export_public_key_iop_t *value);
