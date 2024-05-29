#!/usr/bin/env perl
#
# psa_sim_serialise.pl - Sample Perl script to show how many serialisation
#                        functions can be created by templated scripting.
#
# This is an example only, and is expected to be replaced by a Python script
# for production use. It is not hooked into the build: it needs to be run
# manually:
#
# perl psa_sim_serialise.pl h > psa_sim_serialise.h
# perl psa_sim_serialise.pl c > psa_sim_serialise.c
#
use strict;

my $usage = "$0: usage: $0 c|h\n";
my $which = lc(shift) || die($usage);
die($usage) unless $which eq "c" || $which eq "h";

# Most types are serialised as a fixed-size (per type) octet string, with
# no type indication. This is acceptable as (a) this is for the test PSA crypto
# simulator only, not production, and (b) these functions are called by
# code that itself is written by script.
#
# We also want to keep serialised data reasonably compact as communication
# between client and server goes in messages of less than 200 bytes each.
#
# This script is able to create serialisation functions for plain old C data
# types (e.g. unsigned int), types typedef'd to those, and even structures
# that don't contain pointers.
#
# Structures that contain pointers will need to have their serialisation and
# deserialisation functions written manually (like those for the "buffer" type
# are).
#
my @types = qw(unsigned-int int size_t
               buffer
               psa_status_t psa_algorithm_t
               psa_hash_operation_t);
grep(s/-/ /g, @types);

# IS-A: Some data types are typedef'd; we serialise them as the other type
my %isa = (
    "psa_status_t" => "int",
    "psa_algorithm_t" => "unsigned int",
);

if ($which eq "h") {

    print h_header();

    for my $type (@types) {
        if ($type eq "buffer") {
            print declare_buffer_functions();
        } else {
            print declare_needs($type);
            print declare_serialise($type);
            print declare_deserialise($type);
        }
    }

} elsif ($which eq "c") {

    print c_header();

    for my $type (@types) {
        if ($type eq "buffer") {
            print define_buffer_functions();
        } elsif (exists($isa{$type})) {
            print define_needs_isa($type, $isa{$type});
            print define_serialise_isa($type, $isa{$type});
            print define_deserialise_isa($type, $isa{$type});
        } else {
            print define_needs($type);
            print define_serialise($type);
            print define_deserialise($type);
        }
    }

} else {
    die("internal error - shouldn't happen");
}

sub declare_needs
{
    my ($type) = @_;

    my $an = ($type =~ /^[ui]/) ? "an" : "a";
    my $type_d = $type;
    $type_d =~ s/ /_/g;

    return <<EOF;

/** Return how much buffer space is needed by \\c psasim_serialise_$type_d()
 *  to serialise $an `$type`.
 *
 * \\param value              The value that will be serialised into the buffer
 *                           (needed in case some serialisations are value-
 *                           dependent).
 *
 * \\return                   The number of bytes needed in the buffer by
 *                           \\c psasim_serialise_$type_d() to serialise
 *                           the given value.
 */
size_t psasim_serialise_${type_d}_needs($type value);
EOF
}

sub declare_serialise
{
    my ($type) = @_;

    my $an = ($type =~ /^[ui]/) ? "an" : "a";
    my $type_d = $type;
    $type_d =~ s/ /_/g;

    return align_declaration(<<EOF);

/** Serialise $an `$type` into a buffer.
 *
 * \\param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \\param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \\param value              The value to serialise into the buffer.
 *
 * \\return                   \\c 1 on success ("okay"), \\c 0 on error.
 */
int psasim_serialise_$type_d(uint8_t **pos,
                             size_t *remaining,
                             $type value);
EOF
}

sub declare_deserialise
{
    my ($type) = @_;

    my $an = ($type =~ /^[ui]/) ? "an" : "a";
    my $type_d = $type;
    $type_d =~ s/ /_/g;

    return align_declaration(<<EOF);

/** Deserialise $an `$type` from a buffer.
 *
 * \\param pos[in,out]        Pointer to a `uint8_t *` holding current position
 *                           in the buffer.
 * \\param remaining[in,out]  Pointer to a `size_t` holding number of bytes
 *                           remaining in the buffer.
 * \\param value              Pointer to $an `$type` to receive the value
 *                           deserialised from the buffer.
 *
 * \\return                   \\c 1 on success ("okay"), \\c 0 on error.
 */
int psasim_deserialise_$type_d(uint8_t **pos,
                               size_t *remaining,
                               $type *value);
EOF
}

sub declare_buffer_functions
{
    return <<'EOF';

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
EOF
}

sub h_header
{
    return <<'EOF';
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
EOF
}

sub define_needs
{
    my ($type) = @_;

    my $type_d = $type;
    $type_d =~ s/ /_/g;

    return <<EOF;

size_t psasim_serialise_${type_d}_needs($type value)
{
    return sizeof(value);
}
EOF
}

sub define_needs_isa
{
    my ($type, $isa) = @_;

    my $type_d = $type;
    $type_d =~ s/ /_/g;

    my $isa_d = $isa;
    $isa_d =~ s/ /_/g;

    return <<EOF;

size_t psasim_serialise_${type_d}_needs($type value)
{
    return psasim_serialise_${isa_d}_needs(value);
}
EOF
}

sub define_serialise
{
    my ($type) = @_;

    my $type_d = $type;
    $type_d =~ s/ /_/g;

    return align_signature(<<EOF);

int psasim_serialise_$type_d(uint8_t **pos,
                             size_t *remaining,
                             $type value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}
EOF
}

sub define_serialise_isa
{
    my ($type, $isa) = @_;

    my $type_d = $type;
    $type_d =~ s/ /_/g;

    my $isa_d = $isa;
    $isa_d =~ s/ /_/g;

    return align_signature(<<EOF);

int psasim_serialise_$type_d(uint8_t **pos,
                             size_t *remaining,
                             $type value)
{
    return psasim_serialise_$isa_d(pos, remaining, value);
}
EOF
}

sub define_deserialise
{
    my ($type) = @_;

    my $type_d = $type;
    $type_d =~ s/ /_/g;

    return align_signature(<<EOF);

int psasim_deserialise_$type_d(uint8_t **pos,
                               size_t *remaining,
                               $type *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}
EOF
}

sub define_deserialise_isa
{
    my ($type, $isa) = @_;

    my $type_d = $type;
    $type_d =~ s/ /_/g;

    my $isa_d = $isa;
    $isa_d =~ s/ /_/g;

    return align_signature(<<EOF);

int psasim_deserialise_$type_d(uint8_t **pos,
                              size_t *remaining,
                              $type *value)
{
    return psasim_deserialise_$isa_d(pos, remaining, value);
}
EOF
}

sub define_buffer_functions
{
    return <<'EOF';

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
EOF
}

sub c_header
{
    return <<'EOF';
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
EOF
}

# Horrible way to align first, second and third lines of function signature to
# appease uncrustify (these are the 2nd-4th lines of code, indices 1, 2 and 3)
#
sub align_signature
{
    my ($code) = @_;

    my @code = split(/\n/, $code);

    # Find where the ( is
    my $idx = index($code[1], "(");
    die("can't find (") if $idx < 0;

    my $indent = " " x ($idx + 1);
    $code[2] =~ s/^\s+/$indent/;
    $code[3] =~ s/^\s+/$indent/;

    return join("\n", @code) . "\n";
}

# Horrible way to align the function declaration to appease uncrustify
#
sub align_declaration
{
    my ($code) = @_;

    my @code = split(/\n/, $code);

    # Find out which lines we need to massage
    my $i;
    for ($i = 0; $i <= $#code; $i++) {
        last if $code[$i] =~ /^int psasim_/;
    }
    die("can't find int psasim_") if $i > $#code;

    # Find where the ( is
    my $idx = index($code[$i], "(");
    die("can't find (") if $idx < 0;

    my $indent = " " x ($idx + 1);
    $code[$i + 1] =~ s/^\s+/$indent/;
    $code[$i + 2] =~ s/^\s+/$indent/;

    return join("\n", @code) . "\n";
}
