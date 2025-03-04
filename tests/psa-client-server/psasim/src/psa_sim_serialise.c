/**
 * \file psa_sim_serialise.c
 *
 * \brief Rough-and-ready serialisation and deserialisation for the PSA Crypto simulator
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "psa_sim_serialise.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

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

/* include/psa/crypto_platform.h:typedef uint32_t mbedtls_psa_client_handle_t;
 * but we don't get it on server builds, so redefine it here with a unique type name
 */
typedef uint32_t psasim_client_handle_t;

typedef struct psasim_operation_s {
    psasim_client_handle_t handle;
} psasim_operation_t;

#define MAX_LIVE_HANDLES_PER_CLASS   100        /* this many slots */

static psa_hash_operation_t hash_operations[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t hash_operation_handles[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t next_hash_operation_handle = 1;

/* Get a free slot */
static ssize_t allocate_hash_operation_slot(void)
{
    psasim_client_handle_t handle = next_hash_operation_handle++;
    if (next_hash_operation_handle == 0) {      /* wrapped around */
        FATAL("Hash operation handle wrapped");
    }

    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (hash_operation_handles[i] == 0) {
            hash_operation_handles[i] = handle;
            return i;
        }
    }

    ERROR("All slots are currently used. Unable to allocate a new one.");

    return -1;  /* all in use */
}

/* Find the slot given the handle */
static ssize_t find_hash_slot_by_handle(psasim_client_handle_t handle)
{
    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (hash_operation_handles[i] == handle) {
            return i;
        }
    }

    ERROR("Unable to find slot by handle %u", handle);

    return -1;  /* not found */
}

static psa_aead_operation_t aead_operations[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t aead_operation_handles[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t next_aead_operation_handle = 1;

/* Get a free slot */
static ssize_t allocate_aead_operation_slot(void)
{
    psasim_client_handle_t handle = next_aead_operation_handle++;
    if (next_aead_operation_handle == 0) {      /* wrapped around */
        FATAL("Aead operation handle wrapped");
    }

    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (aead_operation_handles[i] == 0) {
            aead_operation_handles[i] = handle;
            return i;
        }
    }

    ERROR("All slots are currently used. Unable to allocate a new one.");

    return -1;  /* all in use */
}

/* Find the slot given the handle */
static ssize_t find_aead_slot_by_handle(psasim_client_handle_t handle)
{
    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (aead_operation_handles[i] == handle) {
            return i;
        }
    }

    ERROR("Unable to find slot by handle %u", handle);

    return -1;  /* not found */
}

static psa_mac_operation_t mac_operations[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t mac_operation_handles[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t next_mac_operation_handle = 1;

/* Get a free slot */
static ssize_t allocate_mac_operation_slot(void)
{
    psasim_client_handle_t handle = next_mac_operation_handle++;
    if (next_mac_operation_handle == 0) {      /* wrapped around */
        FATAL("Mac operation handle wrapped");
    }

    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (mac_operation_handles[i] == 0) {
            mac_operation_handles[i] = handle;
            return i;
        }
    }

    ERROR("All slots are currently used. Unable to allocate a new one.");

    return -1;  /* all in use */
}

/* Find the slot given the handle */
static ssize_t find_mac_slot_by_handle(psasim_client_handle_t handle)
{
    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (mac_operation_handles[i] == handle) {
            return i;
        }
    }

    ERROR("Unable to find slot by handle %u", handle);

    return -1;  /* not found */
}

static psa_cipher_operation_t cipher_operations[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t cipher_operation_handles[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t next_cipher_operation_handle = 1;

/* Get a free slot */
static ssize_t allocate_cipher_operation_slot(void)
{
    psasim_client_handle_t handle = next_cipher_operation_handle++;
    if (next_cipher_operation_handle == 0) {      /* wrapped around */
        FATAL("Cipher operation handle wrapped");
    }

    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (cipher_operation_handles[i] == 0) {
            cipher_operation_handles[i] = handle;
            return i;
        }
    }

    ERROR("All slots are currently used. Unable to allocate a new one.");

    return -1;  /* all in use */
}

/* Find the slot given the handle */
static ssize_t find_cipher_slot_by_handle(psasim_client_handle_t handle)
{
    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (cipher_operation_handles[i] == handle) {
            return i;
        }
    }

    ERROR("Unable to find slot by handle %u", handle);

    return -1;  /* not found */
}

static psa_key_derivation_operation_t key_derivation_operations[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t key_derivation_operation_handles[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t next_key_derivation_operation_handle = 1;

/* Get a free slot */
static ssize_t allocate_key_derivation_operation_slot(void)
{
    psasim_client_handle_t handle = next_key_derivation_operation_handle++;
    if (next_key_derivation_operation_handle == 0) {      /* wrapped around */
        FATAL("Key_derivation operation handle wrapped");
    }

    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (key_derivation_operation_handles[i] == 0) {
            key_derivation_operation_handles[i] = handle;
            return i;
        }
    }

    ERROR("All slots are currently used. Unable to allocate a new one.");

    return -1;  /* all in use */
}

/* Find the slot given the handle */
static ssize_t find_key_derivation_slot_by_handle(psasim_client_handle_t handle)
{
    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (key_derivation_operation_handles[i] == handle) {
            return i;
        }
    }

    ERROR("Unable to find slot by handle %u", handle);

    return -1;  /* not found */
}

static psa_sign_hash_interruptible_operation_t sign_hash_interruptible_operations[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t sign_hash_interruptible_operation_handles[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t next_sign_hash_interruptible_operation_handle = 1;

/* Get a free slot */
static ssize_t allocate_sign_hash_interruptible_operation_slot(void)
{
    psasim_client_handle_t handle = next_sign_hash_interruptible_operation_handle++;
    if (next_sign_hash_interruptible_operation_handle == 0) {      /* wrapped around */
        FATAL("Sign_hash_interruptible operation handle wrapped");
    }

    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (sign_hash_interruptible_operation_handles[i] == 0) {
            sign_hash_interruptible_operation_handles[i] = handle;
            return i;
        }
    }

    ERROR("All slots are currently used. Unable to allocate a new one.");

    return -1;  /* all in use */
}

/* Find the slot given the handle */
static ssize_t find_sign_hash_interruptible_slot_by_handle(psasim_client_handle_t handle)
{
    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (sign_hash_interruptible_operation_handles[i] == handle) {
            return i;
        }
    }

    ERROR("Unable to find slot by handle %u", handle);

    return -1;  /* not found */
}

static psa_verify_hash_interruptible_operation_t verify_hash_interruptible_operations[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t verify_hash_interruptible_operation_handles[
    MAX_LIVE_HANDLES_PER_CLASS];
static psasim_client_handle_t next_verify_hash_interruptible_operation_handle = 1;

/* Get a free slot */
static ssize_t allocate_verify_hash_interruptible_operation_slot(void)
{
    psasim_client_handle_t handle = next_verify_hash_interruptible_operation_handle++;
    if (next_verify_hash_interruptible_operation_handle == 0) {      /* wrapped around */
        FATAL("Verify_hash_interruptible operation handle wrapped");
    }

    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (verify_hash_interruptible_operation_handles[i] == 0) {
            verify_hash_interruptible_operation_handles[i] = handle;
            return i;
        }
    }

    ERROR("All slots are currently used. Unable to allocate a new one.");

    return -1;  /* all in use */
}

/* Find the slot given the handle */
static ssize_t find_verify_hash_interruptible_slot_by_handle(psasim_client_handle_t handle)
{
    for (ssize_t i = 0; i < MAX_LIVE_HANDLES_PER_CLASS; i++) {
        if (verify_hash_interruptible_operation_handles[i] == handle) {
            return i;
        }
    }

    ERROR("Unable to find slot by handle %u", handle);

    return -1;  /* not found */
}

size_t psasim_serialise_begin_needs(void)
{
    /* The serialisation buffer will
     * start with a byte of 0 to indicate version 0,
     * then have 1 byte each for length of int, long, void *,
     * then have 4 bytes to indicate endianness. */
    return 4 + sizeof(uint32_t);
}

int psasim_serialise_begin(uint8_t **pos, size_t *remaining)
{
    uint32_t endian = 0x1234;

    if (*remaining < 4 + sizeof(endian)) {
        return 0;
    }

    *(*pos)++ = 0;      /* version */
    *(*pos)++ = (uint8_t) sizeof(int);
    *(*pos)++ = (uint8_t) sizeof(long);
    *(*pos)++ = (uint8_t) sizeof(void *);

    memcpy(*pos, &endian, sizeof(endian));

    *pos += sizeof(endian);

    return 1;
}

int psasim_deserialise_begin(uint8_t **pos, size_t *remaining)
{
    uint8_t version = 255;
    uint8_t int_size = 0;
    uint8_t long_size = 0;
    uint8_t ptr_size = 0;
    uint32_t endian;

    if (*remaining < 4 + sizeof(endian)) {
        return 0;
    }

    memcpy(&version, (*pos)++, sizeof(version));
    if (version != 0) {
        return 0;
    }

    memcpy(&int_size, (*pos)++, sizeof(int_size));
    if (int_size != sizeof(int)) {
        return 0;
    }

    memcpy(&long_size, (*pos)++, sizeof(long_size));
    if (long_size != sizeof(long)) {
        return 0;
    }

    memcpy(&ptr_size, (*pos)++, sizeof(ptr_size));
    if (ptr_size != sizeof(void *)) {
        return 0;
    }

    *remaining -= 4;

    memcpy(&endian, *pos, sizeof(endian));
    if (endian != 0x1234) {
        return 0;
    }

    *pos += sizeof(endian);
    *remaining -= sizeof(endian);

    return 1;
}

size_t psasim_serialise_unsigned_int_needs(
    unsigned int value)
{
    return sizeof(value);
}

int psasim_serialise_unsigned_int(uint8_t **pos,
                                  size_t *remaining,
                                  unsigned int value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_unsigned_int(uint8_t **pos,
                                    size_t *remaining,
                                    unsigned int *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_serialise_int_needs(
    int value)
{
    return sizeof(value);
}

int psasim_serialise_int(uint8_t **pos,
                         size_t *remaining,
                         int value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_int(uint8_t **pos,
                           size_t *remaining,
                           int *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_serialise_size_t_needs(
    size_t value)
{
    return sizeof(value);
}

int psasim_serialise_size_t(uint8_t **pos,
                            size_t *remaining,
                            size_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_size_t(uint8_t **pos,
                              size_t *remaining,
                              size_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_serialise_uint16_t_needs(
    uint16_t value)
{
    return sizeof(value);
}

int psasim_serialise_uint16_t(uint8_t **pos,
                              size_t *remaining,
                              uint16_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_uint16_t(uint8_t **pos,
                                size_t *remaining,
                                uint16_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_serialise_uint32_t_needs(
    uint32_t value)
{
    return sizeof(value);
}

int psasim_serialise_uint32_t(uint8_t **pos,
                              size_t *remaining,
                              uint32_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_uint32_t(uint8_t **pos,
                                size_t *remaining,
                                uint32_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_serialise_uint64_t_needs(
    uint64_t value)
{
    return sizeof(value);
}

int psasim_serialise_uint64_t(uint8_t **pos,
                              size_t *remaining,
                              uint64_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_uint64_t(uint8_t **pos,
                                size_t *remaining,
                                uint64_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_serialise_buffer_needs(const uint8_t *buffer, size_t buffer_size)
{
    (void) buffer;
    return sizeof(buffer_size) + buffer_size;
}

int psasim_serialise_buffer(uint8_t **pos,
                            size_t *remaining,
                            const uint8_t *buffer,
                            size_t buffer_length)
{
    if (*remaining < sizeof(buffer_length) + buffer_length) {
        return 0;
    }

    memcpy(*pos, &buffer_length, sizeof(buffer_length));
    *pos += sizeof(buffer_length);

    if (buffer_length > 0) {    // To be able to serialise (NULL, 0)
        memcpy(*pos, buffer, buffer_length);
        *pos += buffer_length;
    }

    return 1;
}

int psasim_deserialise_buffer(uint8_t **pos,
                              size_t *remaining,
                              uint8_t **buffer,
                              size_t *buffer_length)
{
    if (*remaining < sizeof(*buffer_length)) {
        return 0;
    }

    memcpy(buffer_length, *pos, sizeof(*buffer_length));

    *pos += sizeof(buffer_length);
    *remaining -= sizeof(buffer_length);

    if (*buffer_length == 0) {          // Deserialise (NULL, 0)
        *buffer = NULL;
        return 1;
    }

    if (*remaining < *buffer_length) {
        return 0;
    }

    uint8_t *data = malloc(*buffer_length);
    if (data == NULL) {
        return 0;
    }

    memcpy(data, *pos, *buffer_length);
    *pos += *buffer_length;
    *remaining -= *buffer_length;

    *buffer = data;

    return 1;
}

/* When the client is deserialising a buffer returned from the server, it needs
 * to use this function to deserialised the  returned buffer. It should use the
 * usual \c psasim_serialise_buffer() function to serialise the outbound
 * buffer. */
int psasim_deserialise_return_buffer(uint8_t **pos,
                                     size_t *remaining,
                                     uint8_t *buffer,
                                     size_t buffer_length)
{
    if (*remaining < sizeof(buffer_length)) {
        return 0;
    }

    size_t length_check;

    memcpy(&length_check, *pos, sizeof(buffer_length));

    *pos += sizeof(buffer_length);
    *remaining -= sizeof(buffer_length);

    if (buffer_length != length_check) {        // Make sure we're sent back the same we sent to the server
        return 0;
    }

    if (length_check == 0) {          // Deserialise (NULL, 0)
        return 1;
    }

    if (*remaining < buffer_length) {
        return 0;
    }

    memcpy(buffer, *pos, buffer_length);
    *pos += buffer_length;
    *remaining -= buffer_length;

    return 1;
}

size_t psasim_serialise_psa_custom_key_parameters_t_needs(
    psa_custom_key_parameters_t value)
{
    return sizeof(value);
}

int psasim_serialise_psa_custom_key_parameters_t(uint8_t **pos,
                                                 size_t *remaining,
                                                 psa_custom_key_parameters_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_psa_custom_key_parameters_t(uint8_t **pos,
                                                   size_t *remaining,
                                                   psa_custom_key_parameters_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_serialise_psa_status_t_needs(
    psa_status_t value)
{
    return psasim_serialise_int_needs(value);
}

int psasim_serialise_psa_status_t(uint8_t **pos,
                                  size_t *remaining,
                                  psa_status_t value)
{
    return psasim_serialise_int(pos, remaining, value);
}

int psasim_deserialise_psa_status_t(uint8_t **pos,
                                    size_t *remaining,
                                    psa_status_t *value)
{
    return psasim_deserialise_int(pos, remaining, value);
}

size_t psasim_serialise_psa_algorithm_t_needs(
    psa_algorithm_t value)
{
    return psasim_serialise_unsigned_int_needs(value);
}

int psasim_serialise_psa_algorithm_t(uint8_t **pos,
                                     size_t *remaining,
                                     psa_algorithm_t value)
{
    return psasim_serialise_unsigned_int(pos, remaining, value);
}

int psasim_deserialise_psa_algorithm_t(uint8_t **pos,
                                       size_t *remaining,
                                       psa_algorithm_t *value)
{
    return psasim_deserialise_unsigned_int(pos, remaining, value);
}

size_t psasim_serialise_psa_key_derivation_step_t_needs(
    psa_key_derivation_step_t value)
{
    return psasim_serialise_uint16_t_needs(value);
}

int psasim_serialise_psa_key_derivation_step_t(uint8_t **pos,
                                               size_t *remaining,
                                               psa_key_derivation_step_t value)
{
    return psasim_serialise_uint16_t(pos, remaining, value);
}

int psasim_deserialise_psa_key_derivation_step_t(uint8_t **pos,
                                                 size_t *remaining,
                                                 psa_key_derivation_step_t *value)
{
    return psasim_deserialise_uint16_t(pos, remaining, value);
}

size_t psasim_serialise_psa_hash_operation_t_needs(
    psa_hash_operation_t value)
{
    return sizeof(value);
}

int psasim_serialise_psa_hash_operation_t(uint8_t **pos,
                                          size_t *remaining,
                                          psa_hash_operation_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_psa_hash_operation_t(uint8_t **pos,
                                            size_t *remaining,
                                            psa_hash_operation_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_server_serialise_psa_hash_operation_t_needs(
    psa_hash_operation_t *operation)
{
    (void) operation;

    /* We will actually return a handle */
    return sizeof(psasim_operation_t);
}

int psasim_server_serialise_psa_hash_operation_t(uint8_t **pos,
                                                 size_t *remaining,
                                                 psa_hash_operation_t *operation,
                                                 int completed)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(client_operation)) {
        return 0;
    }

    ssize_t slot = operation - hash_operations;

    if (completed) {
        memset(&hash_operations[slot],
               0,
               sizeof(psa_hash_operation_t));
        hash_operation_handles[slot] = 0;
    }

    client_operation.handle = hash_operation_handles[slot];

    memcpy(*pos, &client_operation, sizeof(client_operation));
    *pos += sizeof(client_operation);

    return 1;
}

int psasim_server_deserialise_psa_hash_operation_t(uint8_t **pos,
                                                   size_t *remaining,
                                                   psa_hash_operation_t **operation)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(psasim_operation_t)) {
        return 0;
    }

    memcpy(&client_operation, *pos, sizeof(psasim_operation_t));
    *pos += sizeof(psasim_operation_t);
    *remaining -= sizeof(psasim_operation_t);

    ssize_t slot;
    if (client_operation.handle == 0) {         /* We need a new handle */
        slot = allocate_hash_operation_slot();
    } else {
        slot = find_hash_slot_by_handle(client_operation.handle);
    }

    if (slot < 0) {
        return 0;
    }

    *operation = &hash_operations[slot];

    return 1;
}

size_t psasim_serialise_psa_aead_operation_t_needs(
    psa_aead_operation_t value)
{
    return sizeof(value);
}

int psasim_serialise_psa_aead_operation_t(uint8_t **pos,
                                          size_t *remaining,
                                          psa_aead_operation_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_psa_aead_operation_t(uint8_t **pos,
                                            size_t *remaining,
                                            psa_aead_operation_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_server_serialise_psa_aead_operation_t_needs(
    psa_aead_operation_t *operation)
{
    (void) operation;

    /* We will actually return a handle */
    return sizeof(psasim_operation_t);
}

int psasim_server_serialise_psa_aead_operation_t(uint8_t **pos,
                                                 size_t *remaining,
                                                 psa_aead_operation_t *operation,
                                                 int completed)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(client_operation)) {
        return 0;
    }

    ssize_t slot = operation - aead_operations;

    if (completed) {
        memset(&aead_operations[slot],
               0,
               sizeof(psa_aead_operation_t));
        aead_operation_handles[slot] = 0;
    }

    client_operation.handle = aead_operation_handles[slot];

    memcpy(*pos, &client_operation, sizeof(client_operation));
    *pos += sizeof(client_operation);

    return 1;
}

int psasim_server_deserialise_psa_aead_operation_t(uint8_t **pos,
                                                   size_t *remaining,
                                                   psa_aead_operation_t **operation)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(psasim_operation_t)) {
        return 0;
    }

    memcpy(&client_operation, *pos, sizeof(psasim_operation_t));
    *pos += sizeof(psasim_operation_t);
    *remaining -= sizeof(psasim_operation_t);

    ssize_t slot;
    if (client_operation.handle == 0) {         /* We need a new handle */
        slot = allocate_aead_operation_slot();
    } else {
        slot = find_aead_slot_by_handle(client_operation.handle);
    }

    if (slot < 0) {
        return 0;
    }

    *operation = &aead_operations[slot];

    return 1;
}

size_t psasim_serialise_psa_key_attributes_t_needs(
    psa_key_attributes_t value)
{
    return sizeof(value);
}

int psasim_serialise_psa_key_attributes_t(uint8_t **pos,
                                          size_t *remaining,
                                          psa_key_attributes_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_psa_key_attributes_t(uint8_t **pos,
                                            size_t *remaining,
                                            psa_key_attributes_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_serialise_psa_mac_operation_t_needs(
    psa_mac_operation_t value)
{
    return sizeof(value);
}

int psasim_serialise_psa_mac_operation_t(uint8_t **pos,
                                         size_t *remaining,
                                         psa_mac_operation_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_psa_mac_operation_t(uint8_t **pos,
                                           size_t *remaining,
                                           psa_mac_operation_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_server_serialise_psa_mac_operation_t_needs(
    psa_mac_operation_t *operation)
{
    (void) operation;

    /* We will actually return a handle */
    return sizeof(psasim_operation_t);
}

int psasim_server_serialise_psa_mac_operation_t(uint8_t **pos,
                                                size_t *remaining,
                                                psa_mac_operation_t *operation,
                                                int completed)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(client_operation)) {
        return 0;
    }

    ssize_t slot = operation - mac_operations;

    if (completed) {
        memset(&mac_operations[slot],
               0,
               sizeof(psa_mac_operation_t));
        mac_operation_handles[slot] = 0;
    }

    client_operation.handle = mac_operation_handles[slot];

    memcpy(*pos, &client_operation, sizeof(client_operation));
    *pos += sizeof(client_operation);

    return 1;
}

int psasim_server_deserialise_psa_mac_operation_t(uint8_t **pos,
                                                  size_t *remaining,
                                                  psa_mac_operation_t **operation)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(psasim_operation_t)) {
        return 0;
    }

    memcpy(&client_operation, *pos, sizeof(psasim_operation_t));
    *pos += sizeof(psasim_operation_t);
    *remaining -= sizeof(psasim_operation_t);

    ssize_t slot;
    if (client_operation.handle == 0) {         /* We need a new handle */
        slot = allocate_mac_operation_slot();
    } else {
        slot = find_mac_slot_by_handle(client_operation.handle);
    }

    if (slot < 0) {
        return 0;
    }

    *operation = &mac_operations[slot];

    return 1;
}

size_t psasim_serialise_psa_cipher_operation_t_needs(
    psa_cipher_operation_t value)
{
    return sizeof(value);
}

int psasim_serialise_psa_cipher_operation_t(uint8_t **pos,
                                            size_t *remaining,
                                            psa_cipher_operation_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_psa_cipher_operation_t(uint8_t **pos,
                                              size_t *remaining,
                                              psa_cipher_operation_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_server_serialise_psa_cipher_operation_t_needs(
    psa_cipher_operation_t *operation)
{
    (void) operation;

    /* We will actually return a handle */
    return sizeof(psasim_operation_t);
}

int psasim_server_serialise_psa_cipher_operation_t(uint8_t **pos,
                                                   size_t *remaining,
                                                   psa_cipher_operation_t *operation,
                                                   int completed)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(client_operation)) {
        return 0;
    }

    ssize_t slot = operation - cipher_operations;

    if (completed) {
        memset(&cipher_operations[slot],
               0,
               sizeof(psa_cipher_operation_t));
        cipher_operation_handles[slot] = 0;
    }

    client_operation.handle = cipher_operation_handles[slot];

    memcpy(*pos, &client_operation, sizeof(client_operation));
    *pos += sizeof(client_operation);

    return 1;
}

int psasim_server_deserialise_psa_cipher_operation_t(uint8_t **pos,
                                                     size_t *remaining,
                                                     psa_cipher_operation_t **operation)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(psasim_operation_t)) {
        return 0;
    }

    memcpy(&client_operation, *pos, sizeof(psasim_operation_t));
    *pos += sizeof(psasim_operation_t);
    *remaining -= sizeof(psasim_operation_t);

    ssize_t slot;
    if (client_operation.handle == 0) {         /* We need a new handle */
        slot = allocate_cipher_operation_slot();
    } else {
        slot = find_cipher_slot_by_handle(client_operation.handle);
    }

    if (slot < 0) {
        return 0;
    }

    *operation = &cipher_operations[slot];

    return 1;
}

size_t psasim_serialise_psa_key_derivation_operation_t_needs(
    psa_key_derivation_operation_t value)
{
    return sizeof(value);
}

int psasim_serialise_psa_key_derivation_operation_t(uint8_t **pos,
                                                    size_t *remaining,
                                                    psa_key_derivation_operation_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_psa_key_derivation_operation_t(uint8_t **pos,
                                                      size_t *remaining,
                                                      psa_key_derivation_operation_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_server_serialise_psa_key_derivation_operation_t_needs(
    psa_key_derivation_operation_t *operation)
{
    (void) operation;

    /* We will actually return a handle */
    return sizeof(psasim_operation_t);
}

int psasim_server_serialise_psa_key_derivation_operation_t(uint8_t **pos,
                                                           size_t *remaining,
                                                           psa_key_derivation_operation_t *operation,
                                                           int completed)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(client_operation)) {
        return 0;
    }

    ssize_t slot = operation - key_derivation_operations;

    if (completed) {
        memset(&key_derivation_operations[slot],
               0,
               sizeof(psa_key_derivation_operation_t));
        key_derivation_operation_handles[slot] = 0;
    }

    client_operation.handle = key_derivation_operation_handles[slot];

    memcpy(*pos, &client_operation, sizeof(client_operation));
    *pos += sizeof(client_operation);

    return 1;
}

int psasim_server_deserialise_psa_key_derivation_operation_t(uint8_t **pos,
                                                             size_t *remaining,
                                                             psa_key_derivation_operation_t **operation)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(psasim_operation_t)) {
        return 0;
    }

    memcpy(&client_operation, *pos, sizeof(psasim_operation_t));
    *pos += sizeof(psasim_operation_t);
    *remaining -= sizeof(psasim_operation_t);

    ssize_t slot;
    if (client_operation.handle == 0) {         /* We need a new handle */
        slot = allocate_key_derivation_operation_slot();
    } else {
        slot = find_key_derivation_slot_by_handle(client_operation.handle);
    }

    if (slot < 0) {
        return 0;
    }

    *operation = &key_derivation_operations[slot];

    return 1;
}

size_t psasim_serialise_psa_sign_hash_interruptible_operation_t_needs(
    psa_sign_hash_interruptible_operation_t value)
{
    return sizeof(value);
}

int psasim_serialise_psa_sign_hash_interruptible_operation_t(uint8_t **pos,
                                                             size_t *remaining,
                                                             psa_sign_hash_interruptible_operation_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_psa_sign_hash_interruptible_operation_t(uint8_t **pos,
                                                               size_t *remaining,
                                                               psa_sign_hash_interruptible_operation_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_server_serialise_psa_sign_hash_interruptible_operation_t_needs(
    psa_sign_hash_interruptible_operation_t *operation)
{
    (void) operation;

    /* We will actually return a handle */
    return sizeof(psasim_operation_t);
}

int psasim_server_serialise_psa_sign_hash_interruptible_operation_t(uint8_t **pos,
                                                                    size_t *remaining,
                                                                    psa_sign_hash_interruptible_operation_t *operation,
                                                                    int completed)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(client_operation)) {
        return 0;
    }

    ssize_t slot = operation - sign_hash_interruptible_operations;

    if (completed) {
        memset(&sign_hash_interruptible_operations[slot],
               0,
               sizeof(psa_sign_hash_interruptible_operation_t));
        sign_hash_interruptible_operation_handles[slot] = 0;
    }

    client_operation.handle = sign_hash_interruptible_operation_handles[slot];

    memcpy(*pos, &client_operation, sizeof(client_operation));
    *pos += sizeof(client_operation);

    return 1;
}

int psasim_server_deserialise_psa_sign_hash_interruptible_operation_t(uint8_t **pos,
                                                                      size_t *remaining,
                                                                      psa_sign_hash_interruptible_operation_t **operation)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(psasim_operation_t)) {
        return 0;
    }

    memcpy(&client_operation, *pos, sizeof(psasim_operation_t));
    *pos += sizeof(psasim_operation_t);
    *remaining -= sizeof(psasim_operation_t);

    ssize_t slot;
    if (client_operation.handle == 0) {         /* We need a new handle */
        slot = allocate_sign_hash_interruptible_operation_slot();
    } else {
        slot = find_sign_hash_interruptible_slot_by_handle(client_operation.handle);
    }

    if (slot < 0) {
        return 0;
    }

    *operation = &sign_hash_interruptible_operations[slot];

    return 1;
}

size_t psasim_serialise_psa_verify_hash_interruptible_operation_t_needs(
    psa_verify_hash_interruptible_operation_t value)
{
    return sizeof(value);
}

int psasim_serialise_psa_verify_hash_interruptible_operation_t(uint8_t **pos,
                                                               size_t *remaining,
                                                               psa_verify_hash_interruptible_operation_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_psa_verify_hash_interruptible_operation_t(uint8_t **pos,
                                                                 size_t *remaining,
                                                                 psa_verify_hash_interruptible_operation_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_server_serialise_psa_verify_hash_interruptible_operation_t_needs(
    psa_verify_hash_interruptible_operation_t *operation)
{
    (void) operation;

    /* We will actually return a handle */
    return sizeof(psasim_operation_t);
}

int psasim_server_serialise_psa_verify_hash_interruptible_operation_t(uint8_t **pos,
                                                                      size_t *remaining,
                                                                      psa_verify_hash_interruptible_operation_t *operation,
                                                                      int completed)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(client_operation)) {
        return 0;
    }

    ssize_t slot = operation - verify_hash_interruptible_operations;

    if (completed) {
        memset(&verify_hash_interruptible_operations[slot],
               0,
               sizeof(psa_verify_hash_interruptible_operation_t));
        verify_hash_interruptible_operation_handles[slot] = 0;
    }

    client_operation.handle = verify_hash_interruptible_operation_handles[slot];

    memcpy(*pos, &client_operation, sizeof(client_operation));
    *pos += sizeof(client_operation);

    return 1;
}

int psasim_server_deserialise_psa_verify_hash_interruptible_operation_t(uint8_t **pos,
                                                                        size_t *remaining,
                                                                        psa_verify_hash_interruptible_operation_t **operation)
{
    psasim_operation_t client_operation;

    if (*remaining < sizeof(psasim_operation_t)) {
        return 0;
    }

    memcpy(&client_operation, *pos, sizeof(psasim_operation_t));
    *pos += sizeof(psasim_operation_t);
    *remaining -= sizeof(psasim_operation_t);

    ssize_t slot;
    if (client_operation.handle == 0) {         /* We need a new handle */
        slot = allocate_verify_hash_interruptible_operation_slot();
    } else {
        slot = find_verify_hash_interruptible_slot_by_handle(client_operation.handle);
    }

    if (slot < 0) {
        return 0;
    }

    *operation = &verify_hash_interruptible_operations[slot];

    return 1;
}

size_t psasim_serialise_mbedtls_svc_key_id_t_needs(
    mbedtls_svc_key_id_t value)
{
    return sizeof(value);
}

int psasim_serialise_mbedtls_svc_key_id_t(uint8_t **pos,
                                          size_t *remaining,
                                          mbedtls_svc_key_id_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_mbedtls_svc_key_id_t(uint8_t **pos,
                                            size_t *remaining,
                                            mbedtls_svc_key_id_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_serialise_psa_key_agreement_iop_t_needs(
    psa_key_agreement_iop_t value)
{
    return sizeof(value);
}

int psasim_serialise_psa_key_agreement_iop_t(uint8_t **pos,
                                             size_t *remaining,
                                             psa_key_agreement_iop_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_psa_key_agreement_iop_t(uint8_t **pos,
                                               size_t *remaining,
                                               psa_key_agreement_iop_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_serialise_psa_generate_key_iop_t_needs(
    psa_generate_key_iop_t value)
{
    return sizeof(value);
}

int psasim_serialise_psa_generate_key_iop_t(uint8_t **pos,
                                            size_t *remaining,
                                            psa_generate_key_iop_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_psa_generate_key_iop_t(uint8_t **pos,
                                              size_t *remaining,
                                              psa_generate_key_iop_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_serialise_psa_export_public_key_iop_t_needs(
    psa_export_public_key_iop_t value)
{
    return sizeof(value);
}

int psasim_serialise_psa_export_public_key_iop_t(uint8_t **pos,
                                                 size_t *remaining,
                                                 psa_export_public_key_iop_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_psa_export_public_key_iop_t(uint8_t **pos,
                                                   size_t *remaining,
                                                   psa_export_public_key_iop_t *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

void psa_sim_serialize_reset(void)
{
    memset(hash_operation_handles, 0,
           sizeof(hash_operation_handles));
    memset(hash_operations, 0,
           sizeof(hash_operations));
    memset(aead_operation_handles, 0,
           sizeof(aead_operation_handles));
    memset(aead_operations, 0,
           sizeof(aead_operations));
    memset(mac_operation_handles, 0,
           sizeof(mac_operation_handles));
    memset(mac_operations, 0,
           sizeof(mac_operations));
    memset(cipher_operation_handles, 0,
           sizeof(cipher_operation_handles));
    memset(cipher_operations, 0,
           sizeof(cipher_operations));
    memset(key_derivation_operation_handles, 0,
           sizeof(key_derivation_operation_handles));
    memset(key_derivation_operations, 0,
           sizeof(key_derivation_operations));
    memset(sign_hash_interruptible_operation_handles, 0,
           sizeof(sign_hash_interruptible_operation_handles));
    memset(sign_hash_interruptible_operations, 0,
           sizeof(sign_hash_interruptible_operations));
    memset(verify_hash_interruptible_operation_handles, 0,
           sizeof(verify_hash_interruptible_operation_handles));
    memset(verify_hash_interruptible_operations, 0,
           sizeof(verify_hash_interruptible_operations));
}
