/* Copyright (c) INRIA and Microsoft Corporation. All rights reserved.
   Licensed under the Apache 2.0 License. */

/******************************************************************************/
/* Machine integers (128-bit arithmetic)                                      */
/******************************************************************************/

/* This header makes KreMLin-generated C code work with:
 * - the default setting where we assume the target compiler defines __int128
 * - the setting where we use FStar.UInt128's implementation instead; in that
 *   case, generated C files must be compiled with -DKRML_VERIFIED_UINT128
 * - a refinement of the case above, wherein all structures are passed by
 *   reference, a.k.a. "-fnostruct-passing", meaning that the KreMLin-generated
 *   must be compiled with -DKRML_NOSTRUCT_PASSING
 * Note: no MSVC support in this file.
 */

#include "FStar_UInt128.h"
#include "kremlin/c_endianness.h"
#include "FStar_UInt64_FStar_UInt32_FStar_UInt16_FStar_UInt8.h"

#if !defined(KRML_VERIFIED_UINT128) && !defined(_MSC_VER)

/* GCC + using native unsigned __int128 support */

uint128_t load128_le(uint8_t *b) {
  uint128_t l = (uint128_t)load64_le(b);
  uint128_t h = (uint128_t)load64_le(b + 8);
  return (h << 64 | l);
}

void store128_le(uint8_t *b, uint128_t n) {
  store64_le(b, (uint64_t)n);
  store64_le(b + 8, (uint64_t)(n >> 64));
}

uint128_t load128_be(uint8_t *b) {
  uint128_t h = (uint128_t)load64_be(b);
  uint128_t l = (uint128_t)load64_be(b + 8);
  return (h << 64 | l);
}

void store128_be(uint8_t *b, uint128_t n) {
  store64_be(b, (uint64_t)(n >> 64));
  store64_be(b + 8, (uint64_t)n);
}

uint128_t FStar_UInt128_add(uint128_t x, uint128_t y) {
  return x + y;
}

uint128_t FStar_UInt128_mul(uint128_t x, uint128_t y) {
  return x * y;
}

uint128_t FStar_UInt128_add_mod(uint128_t x, uint128_t y) {
  return x + y;
}

uint128_t FStar_UInt128_sub(uint128_t x, uint128_t y) {
  return x - y;
}

uint128_t FStar_UInt128_sub_mod(uint128_t x, uint128_t y) {
  return x - y;
}

uint128_t FStar_UInt128_logand(uint128_t x, uint128_t y) {
  return x & y;
}

uint128_t FStar_UInt128_logor(uint128_t x, uint128_t y) {
  return x | y;
}

uint128_t FStar_UInt128_logxor(uint128_t x, uint128_t y) {
  return x ^ y;
}

uint128_t FStar_UInt128_lognot(uint128_t x) {
  return ~x;
}

uint128_t FStar_UInt128_shift_left(uint128_t x, uint32_t y) {
  return x << y;
}

uint128_t FStar_UInt128_shift_right(uint128_t x, uint32_t y) {
  return x >> y;
}

uint128_t FStar_UInt128_uint64_to_uint128(uint64_t x) {
  return (uint128_t)x;
}

uint64_t FStar_UInt128_uint128_to_uint64(uint128_t x) {
  return (uint64_t)x;
}

uint128_t FStar_UInt128_mul_wide(uint64_t x, uint64_t y) {
  return ((uint128_t) x) * y;
}

uint128_t FStar_UInt128_eq_mask(uint128_t x, uint128_t y) {
  uint64_t mask =
      FStar_UInt64_eq_mask((uint64_t)(x >> 64), (uint64_t)(y >> 64)) &
      FStar_UInt64_eq_mask(x, y);
  return ((uint128_t)mask) << 64 | mask;
}

uint128_t FStar_UInt128_gte_mask(uint128_t x, uint128_t y) {
  uint64_t mask =
      (FStar_UInt64_gte_mask(x >> 64, y >> 64) &
       ~(FStar_UInt64_eq_mask(x >> 64, y >> 64))) |
      (FStar_UInt64_eq_mask(x >> 64, y >> 64) & FStar_UInt64_gte_mask(x, y));
  return ((uint128_t)mask) << 64 | mask;
}

uint128_t FStar_Int_Cast_Full_uint64_to_uint128(uint64_t x) {
  return x;
}

uint64_t FStar_Int_Cast_Full_uint128_to_uint64(uint128_t x) {
  return x;
}

#elif !defined(_MSC_VER) && defined(KRML_VERIFIED_UINT128)

/* Verified uint128 implementation. */

/* Access 64-bit fields within the int128. */
#define HIGH64_OF(x) ((x)->high)
#define LOW64_OF(x)  ((x)->low)

typedef FStar_UInt128_uint128 FStar_UInt128_t_, uint128_t;

/* A series of definitions written using pointers. */

void load128_le_(uint8_t *b, uint128_t *r) {
  LOW64_OF(r) = load64_le(b);
  HIGH64_OF(r) = load64_le(b + 8);
}

void store128_le_(uint8_t *b, uint128_t *n) {
  store64_le(b, LOW64_OF(n));
  store64_le(b + 8, HIGH64_OF(n));
}

void load128_be_(uint8_t *b, uint128_t *r) {
  HIGH64_OF(r) = load64_be(b);
  LOW64_OF(r) = load64_be(b + 8);
}

void store128_be_(uint8_t *b, uint128_t *n) {
  store64_be(b, HIGH64_OF(n));
  store64_be(b + 8, LOW64_OF(n));
}

void
FStar_Int_Cast_Full_uint64_to_uint128_(uint64_t x, uint128_t *dst) {
  /* C89 */
  LOW64_OF(dst) = x;
  HIGH64_OF(dst) = 0;
}

uint64_t FStar_Int_Cast_Full_uint128_to_uint64_(uint128_t *x) {
  return LOW64_OF(x);
}

#    ifndef KRML_NOSTRUCT_PASSING

uint128_t load128_le(uint8_t *b) {
  uint128_t r;
  load128_le_(b, &r);
  return r;
}

void store128_le(uint8_t *b, uint128_t n) {
  store128_le_(b, &n);
}

uint128_t load128_be(uint8_t *b) {
  uint128_t r;
  load128_be_(b, &r);
  return r;
}

void store128_be(uint8_t *b, uint128_t n) {
  store128_be_(b, &n);
}

uint128_t FStar_Int_Cast_Full_uint64_to_uint128(uint64_t x) {
  uint128_t dst;
  FStar_Int_Cast_Full_uint64_to_uint128_(x, &dst);
  return dst;
}

uint64_t FStar_Int_Cast_Full_uint128_to_uint64(uint128_t x) {
  return FStar_Int_Cast_Full_uint128_to_uint64_(&x);
}

#    else /* !defined(KRML_STRUCT_PASSING) */

#      define print128 print128_
#      define load128_le load128_le_
#      define store128_le store128_le_
#      define load128_be load128_be_
#      define store128_be store128_be_
#      define FStar_Int_Cast_Full_uint128_to_uint64                            \
        FStar_Int_Cast_Full_uint128_to_uint64_
#      define FStar_Int_Cast_Full_uint64_to_uint128                            \
        FStar_Int_Cast_Full_uint64_to_uint128_

#    endif /* KRML_STRUCT_PASSING */

#endif
