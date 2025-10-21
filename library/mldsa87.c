/*
 *  Copyright 2024 The BoringSSL Authors
 *  Copyright 2025 Google LLC
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_MLDSA_C)

#include "constant_time_internal.h"
#include "mbedtls/mldsa87.h"
#include "mbedtls/sha3.h"

/* Arithmetic parameters. */

// 2^23 - 2^13 + 1
#define K_PRIME 8380417
// Inverse of -K_PRIME modulo 2^32
#define K_PRIME_NEG_INVERSE 4236238847
#define K_DROPPED_BITS 13
#define K_HALF_PRIME ((K_PRIME - 1) / 2)
#define K_DEGREE 256
// 256^-1 mod K_PRIME, in Montgomery form.
#define K_INVERSE_DEGREE_MONTGOMERY 41978

/* Common sizes. */

#define K_RHO_BYTES 32
#define K_SIGMA_BYTES 64
#define K_K_BYTES 32
#define K_TR_BYTES 64
#define K_MU_BYTES 64
#define K_RHO_PRIME_BYTES 64

/* ML-DSA-87 parameters. */

#define TAU 60
#define LAMBDA_BYTES (256 / 8)
#define GAMMA1 (1 << 19)
#define K_GAMMA_2 ((K_PRIME - 1) / 32)
#define BETA 120
#define OMEGA 75

/* Fundamental types. */

typedef struct {
  uint32_t c[K_DEGREE];
} scalar_t;

typedef struct {
  scalar_t v[8];
} vector8_t;

typedef struct {
  scalar_t v[7];
} vector7_t;

/* Complex types. */

typedef struct {
  uint8_t rho[K_RHO_BYTES];
  vector8_t t1;
  // We cache the public key hash.
  uint8_t public_key_hash[K_TR_BYTES];
} public_key_t;

typedef struct {
  uint8_t rho[K_RHO_BYTES];
  uint8_t k[K_K_BYTES];
  uint8_t public_key_hash[K_TR_BYTES];
  // We keep these in NTT form to save stack space during signing.
  vector7_t s1_ntt;
  vector8_t s2_ntt;
  vector8_t t0_ntt;
} private_key_t;

typedef struct {
  uint8_t c_tilde[2 * LAMBDA_BYTES];
  vector7_t z;
  vector8_t h;
} signature_t;

/* Arithmetic. */

static const uint32_t kNTTRootsMontgomery[K_DEGREE] = {
    4193792, 25847,   5771523, 7861508, 237124,  7602457, 7504169, 466468,
    1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
    2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
    6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005,
    2706023, 95776,   3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
    4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
    6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
    811944,  531354,  954230,  3881043, 3900724, 5823537, 2071892, 5582638,
    4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
    7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922,
    3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
    7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
    5037034, 264944,  508951,  3097992, 44288,   7280319, 904516,  3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969,  7063561,
    189548,  4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
    1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
    2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
    266997,  2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
    900702,  1859098, 909542,  819034,  495491,  6767243, 8337157, 7857917,
    7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
    342297,  286988,  5942594, 4108315, 3437287, 5038140, 1735879, 203044,
    2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
    4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
    7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
    7100756, 1917081, 5834105, 7005614, 1500165, 777191,  2235880, 3406031,
    7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136,  4603424,
    6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531,  7173032,
    5196991, 162844,  1616392, 3014001, 810149,  1652634, 4686184, 6581310,
    5341501, 3523897, 3866901, 269760,  2213111, 7404533, 1717735, 472078,
    7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
    5441381, 6144432, 7959518, 6094090, 183443,  7403526, 1612842, 4834730,
    7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782};

// Reduces x mod K_PRIME in constant time, where 0 <= x < 2*K_PRIME.
static uint32_t reduce_once(uint32_t x)
{
  // return x < K_PRIME ? x : x - K_PRIME;
  return mbedtls_ct_if(mbedtls_ct_uint_lt(x, K_PRIME), x, x - K_PRIME);
}

// Returns the absolute value in constant time.
static uint32_t abs_signed(uint32_t x)
{
  // return is_positive(x) ? x : -x;
  return mbedtls_ct_if(mbedtls_ct_uint_lt(x, 0x80000000), x, 0u - x);
}

// Returns the absolute value modulo K_PRIME.
static uint32_t abs_mod_prime(uint32_t x)
{
  // return x > K_HALF_PRIME ? K_PRIME - x : x;
  return mbedtls_ct_if(mbedtls_ct_uint_lt(K_HALF_PRIME, x), K_PRIME - x, x);
}

// Returns the maximum of two values in constant time.
static uint32_t maximum(uint32_t x, uint32_t y)
{
  // return x < y ? y : x;
  return mbedtls_ct_if(mbedtls_ct_uint_lt(x, y), y, x);
}

static uint32_t mod_sub(uint32_t a, uint32_t b)
{
  return reduce_once(K_PRIME + a - b);
}

static void scalar_add(scalar_t *out, const scalar_t *lhs, const scalar_t *rhs)
{
  for (size_t i = 0; i < K_DEGREE; i++) {
    out->c[i] = reduce_once(lhs->c[i] + rhs->c[i]);
  }
}

static void scalar_sub(scalar_t *out, const scalar_t *lhs, const scalar_t *rhs)
{
  for (size_t i = 0; i < K_DEGREE; i++) {
    out->c[i] = mod_sub(lhs->c[i], rhs->c[i]);
  }
}

static uint32_t reduce_montgomery(uint64_t x)
{
  uint64_t a = (uint32_t)(x * K_PRIME_NEG_INVERSE);
  uint64_t b = x + a * K_PRIME;
  uint32_t c = b >> 32;
  return reduce_once(c);
}

// Multiply two scalars in NTT form.
static void scalar_mul(scalar_t *out, const scalar_t *lhs, const scalar_t *rhs)
{
  for (size_t i = 0; i < K_DEGREE; i++) {
    out->c[i] = reduce_montgomery((uint64_t)lhs->c[i] * (uint64_t)rhs->c[i]);
  }
}

// For scalars a, b, c in NTT form, compute a + b * c.
static void scalar_mul_add(scalar_t *out, const scalar_t *a, const scalar_t *b, const scalar_t *c)
{
  for (size_t i = 0; i < K_DEGREE; i++) {
    out->c[i] = reduce_once(a->c[i] + reduce_montgomery((uint64_t)b->c[i] * (uint64_t)c->c[i]));
  }
}

// In place number theoretic transform of a given scalar.
//
// FIPS 204, Algorithm 41 (`NTT`).
static void scalar_ntt(scalar_t *s)
{
  // Step: 1, 2, 4, 8, ..., 128
  // Offset: 128, 64, 32, 16, ..., 1
  int offset = K_DEGREE;
  for (size_t step = 1; step < K_DEGREE; step <<= 1) {
    offset >>= 1;
    int k = 0;
    for (size_t i = 0; i < step; i++) {
      const uint32_t step_root = kNTTRootsMontgomery[step + i];
      for (size_t j = k; j < k + offset; j++) {
        uint32_t even = s->c[j];
        // |reduce_montgomery| works on values up to K_PRIME*R and R > 2*K_PRIME.
        // |step_root| < K_PRIME because it's static data. |s->c[...]| is <
        // K_PRIME by the invariants of that struct.
        uint32_t odd = reduce_montgomery((uint64_t)step_root * (uint64_t)s->c[j + offset]);
        s->c[j] = reduce_once(odd + even);
        s->c[j + offset] = mod_sub(even, odd);
      }
      k += 2 * offset;
    }
  }
}

// In place inverse number theoretic transform of a given scalar.
//
// FIPS 204, Algorithm 42 (`NTT^-1`).
static void scalar_inverse_ntt(scalar_t *s)
{
  // Step: 128, 64, 32, 16, ..., 1
  // Offset: 1, 2, 4, 8, ..., 128
  int step = K_DEGREE;
  for (size_t offset = 1; offset < K_DEGREE; offset <<= 1) {
    step >>= 1;
    int k = 0;
    for (size_t i = 0; i < step; i++) {
      const uint32_t step_root =
          K_PRIME - kNTTRootsMontgomery[step + (step - 1 - i)];
      for (size_t j = k; j < k + offset; j++) {
        uint32_t even = s->c[j];
        uint32_t odd = s->c[j + offset];
        s->c[j] = reduce_once(odd + even);
        // |reduce_montgomery| works on values up to K_PRIME*R and R > 2*K_PRIME.
        // K_PRIME + even < 2*K_PRIME because |even| < K_PRIME, by the invariants
        // of that structure. Thus K_PRIME + even - odd < 2*K_PRIME because odd >=
        // 0, because it's unsigned and less than K_PRIME. Lastly step_root <
        // K_PRIME, because |kNTTRootsMontgomery| is static data.
        s->c[j + offset] = reduce_montgomery((uint64_t)step_root * (uint64_t)(K_PRIME + even - odd));
      }
      k += 2 * offset;
    }
  }
  for (size_t i = 0; i < K_DEGREE; i++) {
    s->c[i] = reduce_montgomery((uint64_t)s->c[i] * (uint64_t)K_INVERSE_DEGREE_MONTGOMERY);
  }
}

static void vector8_zero(vector8_t *out)
{
  memset(&out->v, 0, sizeof(out->v));
}

static void vector8_add(vector8_t *out, const vector8_t *lhs, const vector8_t *rhs)
{
  for (size_t i = 0; i < 8; i++) {
    scalar_add(&out->v[i], &lhs->v[i], &rhs->v[i]);
  }
}

static void vector7_add(vector7_t *out, const vector7_t *lhs, const vector7_t *rhs)
{
  for (size_t i = 0; i < 7; i++) {
    scalar_add(&out->v[i], &lhs->v[i], &rhs->v[i]);
  }
}

static void vector8_sub(vector8_t *out, const vector8_t *lhs, const vector8_t *rhs)
{
  for (size_t i = 0; i < 8; i++) {
    scalar_sub(&out->v[i], &lhs->v[i], &rhs->v[i]);
  }
}

static void vector8_mul_scalar(vector8_t *out, const vector8_t *lhs, const scalar_t *rhs)
{
  for (size_t i = 0; i < 8; i++) {
    scalar_mul(&out->v[i], &lhs->v[i], rhs);
  }
}

static void vector7_mul_scalar(vector7_t *out, const vector7_t *lhs, const scalar_t *rhs)
{
  for (size_t i = 0; i < 7; i++) {
    scalar_mul(&out->v[i], &lhs->v[i], rhs);
  }
}

static void vector8_ntt(vector8_t *a)
{
  for (size_t i = 0; i < 8; i++) {
    scalar_ntt(&a->v[i]);
  }
}

static void vector7_ntt(vector7_t *a)
{
  for (size_t i = 0; i < 7; i++) {
    scalar_ntt(&a->v[i]);
  }
}

static void vector8_inverse_ntt(vector8_t *a)
{
  for (size_t i = 0; i < 8; i++) {
    scalar_inverse_ntt(&a->v[i]);
  }
}

static void vector7_inverse_ntt(vector7_t *a)
{
  for (size_t i = 0; i < 7; i++) {
    scalar_inverse_ntt(&a->v[i]);
  }
}

/* Rounding and hints. */

// FIPS 204, Algorithm 35 (`Power2Round`).
static void power2_round(uint32_t *r1, uint32_t *r0, uint32_t r)
{
  *r1 = r >> K_DROPPED_BITS;
  *r0 = r - (*r1 << K_DROPPED_BITS);

  uint32_t r0_adjusted = mod_sub(*r0, 1 << K_DROPPED_BITS);
  uint32_t r1_adjusted = *r1 + 1;

  // Mask is set iff r0 > 2^(dropped_bits - 1).
  mbedtls_ct_condition_t cond = mbedtls_ct_uint_lt((uint32_t)(1 << (K_DROPPED_BITS - 1)), *r0);
  // r0 = cond ? r0_adjusted : r0
  *r0 = mbedtls_ct_if(cond, r0_adjusted, *r0);
  // r1 = cond ? r1_adjusted : r1
  *r1 = mbedtls_ct_if(cond, r1_adjusted, *r1);
}

// Scale back previously rounded value.
static void scale_power2_round(uint32_t *out, uint32_t r1)
{
  // Pre-condition: 0 <= r1 <= 2^10 - 1
  *out = r1 << K_DROPPED_BITS;
  // Post-condition: 0 <= out <= 2^23 - 2^13 = K_PRIME - 1
}

// FIPS 204, Algorithm 37 (`HighBits`).
static uint32_t high_bits(uint32_t x)
{
  // Reference description (given 0 <= x < q):
  //
  // ```
  // int32_t r0 = x mod+- (2 * gamma2);
  // if (x - r0 == q - 1) {
  //   return 0;
  // } else {
  //   return (x - r0) / (2 * gamma2);
  // }
  // ```
  //
  // Below is the formula taken from the reference implementation.
  //
  // Here, gamma2 == 2^18 - 2^8
  // This returns ((ceil(x / 2^7) * (2^10 + 1) + 2^21) / 2^22) mod 2^4
  uint32_t r1 = (x + 127) >> 7;
  r1 = (r1 * 1025 + (1 << 21)) >> 22;
  r1 &= 15;
  return r1;
}

// FIPS 204, Algorithm 36 (`Decompose`).
static void decompose(uint32_t *r1, int32_t *r0, uint32_t r)
{
  *r1 = high_bits(r);

  *r0 = r;
  *r0 -= *r1 * 2 * (int32_t)K_GAMMA_2;
  *r0 -= (((int32_t)K_HALF_PRIME - *r0) >> 31) & (int32_t)K_PRIME;
}

// FIPS 204, Algorithm 38 (`LowBits`).
static int32_t low_bits(uint32_t x)
{
  uint32_t r1;
  int32_t r0;
  decompose(&r1, &r0, x);
  return r0;
}

// FIPS 204, Algorithm 39 (`MakeHint`).
//
// In the spec this takes two arguments, z and r, and is called with
//   z = -ct0
//   r = w - cs2 + ct0
//
// It then computes HighBits (algorithm 37) of z and z+r. But z+r is just w -
// cs2, so this takes three arguments and saves an addition.
static int32_t make_hint(uint32_t ct0, uint32_t cs2, uint32_t w)
{
  uint32_t r_plus_z = mod_sub(w, cs2);
  uint32_t r = reduce_once(r_plus_z + ct0);
  return high_bits(r) != high_bits(r_plus_z);
}

// FIPS 204, Algorithm 40 (`UseHint`).
static uint32_t use_hint(uint32_t h, uint32_t r)
{
  uint32_t r1;
  int32_t r0;
  decompose(&r1, &r0, r);

  if (h) {
    if (r0 > 0) {
      // m = 16, thus |mod m| in the spec turns into |& 15|.
      return (r1 + 1) & 15;
    } else {
      return (r1 - 1) & 15;
    }
  }
  return r1;
}

static void scalar_power2_round(scalar_t *s1, scalar_t *s0, const scalar_t *s)
{
  for (size_t i = 0; i < K_DEGREE; i++) {
    power2_round(&s1->c[i], &s0->c[i], s->c[i]);
  }
}

static void scalar_scale_power2_round(scalar_t *out, const scalar_t *in)
{
  for (size_t i = 0; i < K_DEGREE; i++) {
    scale_power2_round(&out->c[i], in->c[i]);
  }
}

static void scalar_high_bits(scalar_t *out, const scalar_t *in)
{
  for (size_t i = 0; i < K_DEGREE; i++) {
    out->c[i] = high_bits(in->c[i]);
  }
}

static void scalar_low_bits(scalar_t *out, const scalar_t *in)
{
  for (size_t i = 0; i < K_DEGREE; i++) {
    out->c[i] = low_bits(in->c[i]);
  }
}

static void scalar_max(uint32_t *max, const scalar_t *s)
{
  for (size_t i = 0; i < K_DEGREE; i++) {
    uint32_t abs = abs_mod_prime(s->c[i]);
    *max = maximum(*max, abs);
  }
}

static void scalar_max_signed(uint32_t *max, const scalar_t *s)
{
  for (size_t i = 0; i < K_DEGREE; i++) {
    uint32_t abs = abs_signed(s->c[i]);
    *max = maximum(*max, abs);
  }
}

static void scalar_make_hint(scalar_t *out, const scalar_t *ct0, const scalar_t *cs2, const scalar_t *w)
{
  for (size_t i = 0; i < K_DEGREE; i++) {
    out->c[i] = make_hint(ct0->c[i], cs2->c[i], w->c[i]);
  }
}

static void scalar_use_hint(scalar_t *out, const scalar_t *h, const scalar_t *r)
{
  for (size_t i = 0; i < K_DEGREE; i++) {
    out->c[i] = use_hint(h->c[i], r->c[i]);
  }
}

static void vector8_power2_round(vector8_t *t1, vector8_t *t0, const vector8_t *t)
{
  for (size_t i = 0; i < 8; i++) {
    scalar_power2_round(&t1->v[i], &t0->v[i], &t->v[i]);
  }
}

static void vector8_scale_power2_round(vector8_t *out, const vector8_t *in)
{
  for (size_t i = 0; i < 8; i++) {
    scalar_scale_power2_round(&out->v[i], &in->v[i]);
  }
}

static void vector8_high_bits(vector8_t *out, const vector8_t *in)
{
  for (size_t i = 0; i < 8; i++) {
    scalar_high_bits(&out->v[i], &in->v[i]);
  }
}

static void vector8_low_bits(vector8_t *out, const vector8_t *in)
{
  for (size_t i = 0; i < 8; i++) {
    scalar_low_bits(&out->v[i], &in->v[i]);
  }
}

static uint32_t vector8_max(const vector8_t *a)
{
  uint32_t max = 0;
  for (size_t i = 0; i < 8; i++) {
    scalar_max(&max, &a->v[i]);
  }
  return max;
}

static uint32_t vector7_max(const vector7_t *a)
{
  uint32_t max = 0;
  for (size_t i = 0; i < 7; i++) {
    scalar_max(&max, &a->v[i]);
  }
  return max;
}

static uint32_t vector8_max_signed(const vector8_t *a)
{
  uint32_t max = 0;
  for (size_t i = 0; i < 8; i++) {
    scalar_max_signed(&max, &a->v[i]);
  }
  return max;
}

// The input vector contains only zeroes and ones.
static size_t vector8_count_ones(const vector8_t *a)
{
  size_t count = 0;
  for (size_t i = 0; i < 8; i++) {
    for (size_t j = 0; j < K_DEGREE; j++) {
      count += a->v[i].c[j];
    }
  }
  return count;
}

static void vector8_make_hint(vector8_t *out, const vector8_t *ct0, const vector8_t *cs2, const vector8_t *w)
{
  for (size_t i = 0; i < 8; i++) {
    scalar_make_hint(&out->v[i], &ct0->v[i], &cs2->v[i], &w->v[i]);
  }
}

static void vector8_use_hint(vector8_t *out, const vector8_t *h, const vector8_t *r)
{
  for (size_t i = 0; i < 8; i++) {
    scalar_use_hint(&out->v[i], &h->v[i], &r->v[i]);
  }
}

/* Bit packing. */

// FIPS 204, Algorithm 16 (`SimpleBitPack`). Specialized to bitlen(b) = 4.
static void scalar_encode_4(uint8_t out[128], const scalar_t *s)
{
  for (size_t i = 0; i < K_DEGREE / 2; i++) {
    uint32_t a = s->c[2 * i];
    uint32_t b = s->c[2 * i + 1];
    out[i] = a | (b << 4);
  }
}

// FIPS 204, Algorithm 16 (`SimpleBitPack`). Specialized to bitlen(b) = 10.
static void scalar_encode_10(uint8_t out[320], const scalar_t *s)
{
  for (size_t i = 0; i < K_DEGREE / 4; i++) {
    uint32_t a = s->c[4 * i];
    uint32_t b = s->c[4 * i + 1];
    uint32_t c = s->c[4 * i + 2];
    uint32_t d = s->c[4 * i + 3];
    out[5 * i] = (uint8_t)a;
    out[5 * i + 1] = (uint8_t)((a >> 8) | (b << 2));
    out[5 * i + 2] = (uint8_t)((b >> 6) | (c << 4));
    out[5 * i + 3] = (uint8_t)((c >> 4) | (d << 6));
    out[5 * i + 4] = (uint8_t)(d >> 2);
  }
}

// FIPS 204, Algorithm 17 (`BitPack`). Specialized to bitlen(a+b) = 20 and b = 2^19.
static void scalar_encode_signed_20_19(uint8_t out[640], const scalar_t *s)
{
  const uint32_t kMax = 1u << 19;
  for (size_t i = 0; i < K_DEGREE / 4; i++) {
    uint32_t a = mod_sub(kMax, s->c[4 * i]);
    uint32_t b = mod_sub(kMax, s->c[4 * i + 1]);
    uint32_t c = mod_sub(kMax, s->c[4 * i + 2]);
    uint32_t d = mod_sub(kMax, s->c[4 * i + 3]);
    a |= b << 20;
    b >>= 12;
    b |= c << 8;
    b |= d << 28;
    d >>= 4;
    memcpy(&out[10 * i], &a, sizeof(a));
    memcpy(&out[10 * i + 4], &b, sizeof(b));
    memcpy(&out[10 * i + 8], &d, 2);
  }
}

// FIPS 204, Algorithm 18 (`SimpleBitUnpack`). Specialized for bitlen(b) == 10.
static void scalar_decode_10(scalar_t *out, const uint8_t in[320])
{
  uint32_t v;
  for (size_t i = 0; i < K_DEGREE / 4; i++) {
    memcpy(&v, &in[5 * i], sizeof(v));
    out->c[4 * i] = v & 0x3FF;
    out->c[4 * i + 1] = (v >> 10) & 0x3FF;
    out->c[4 * i + 2] = (v >> 20) & 0x3FF;
    out->c[4 * i + 3] = (v >> 30) | (((uint32_t)in[5 * i + 4]) << 2);
  }
}

// FIPS 204, Algorithm 19 (`BitUnpack`). Specialized to bitlen(a+b) = 20 and b = 2^19.
static void scalar_decode_signed_20_19(scalar_t *out, const uint8_t in[640])
{
  const uint32_t kMax = 1u << 19;
  const uint32_t k20Bits = (1u << 20) - 1;

  uint32_t a, b;
  uint16_t c;
  for (size_t i = 0; i < K_DEGREE / 4; i++) {
    memcpy(&a, &in[10 * i], sizeof(a));
    memcpy(&b, &in[10 * i + 4], sizeof(b));
    memcpy(&c, &in[10 * i + 8], sizeof(c));

    // It's not possible for a 20-bit number to be out of range when the max is 2^19.
    out->c[i * 4] = mod_sub(kMax, a & k20Bits);
    out->c[i * 4 + 1] = mod_sub(kMax, (a >> 20) | ((b & 0xFF) << 12));
    out->c[i * 4 + 2] = mod_sub(kMax, (b >> 8) & k20Bits);
    out->c[i * 4 + 3] = mod_sub(kMax, (b >> 28) | ((uint32_t)c) << 4);
  }
}

/* Expansion functions. */

// FIPS 204, Algorithm 30 (`RejNTTPoly`).
//
// Rejection samples a Keccak stream to get uniformly distributed elements. This
// is used for matrix expansion and only operates on public inputs.
static void scalar_from_keccak_vartime(scalar_t *out, const uint8_t derived_seed[K_RHO_BYTES + 2])
{
  mbedtls_sha3_context shake128_ctxt;
  mbedtls_sha3_init(&shake128_ctxt);
  mbedtls_sha3_starts(&shake128_ctxt, MBEDTLS_SHA3_SHAKE128);
  mbedtls_sha3_update(&shake128_ctxt, derived_seed, K_RHO_BYTES + 2);

  int done = 0;
  while (done < K_DEGREE) {
    uint8_t block[168];
    mbedtls_sha3_finish(&shake128_ctxt, block, sizeof(block));
    for (size_t i = 0; i < sizeof(block) && done < K_DEGREE; i += 3) {
      // FIPS 204, Algorithm 14 (`CoeffFromThreeBytes`).
      uint32_t value = (uint32_t)block[i] | ((uint32_t)block[i + 1] << 8) |
                       (((uint32_t)block[i + 2] & 0x7F) << 16);
      if (value < K_PRIME) {
        out->c[done++] = value;
      }
    }
  }

  mbedtls_sha3_free(&shake128_ctxt);
}

static int coefficient_from_nibble_2(uint32_t nibble, uint32_t *result)
{
  if (nibble < 15) {
    *result = mod_sub(2, nibble % 5);
    return 1;
  }
  return 0;
}

// FIPS 204, Algorithm 31 (`RejBoundedPoly`).
static void scalar_uniform_2(scalar_t *out, const uint8_t derived_seed[K_SIGMA_BYTES + 2])
{
  mbedtls_sha3_context shake256_ctxt;
  mbedtls_sha3_init(&shake256_ctxt);
  mbedtls_sha3_starts(&shake256_ctxt, MBEDTLS_SHA3_SHAKE256);
  mbedtls_sha3_update(&shake256_ctxt, derived_seed, K_SIGMA_BYTES + 2);

  int done = 0;
  while (done < K_DEGREE) {
    uint8_t block[136];
    mbedtls_sha3_finish(&shake256_ctxt, block, sizeof(block));
    for (size_t i = 0; i < sizeof(block) && done < K_DEGREE; ++i) {
      uint32_t t0 = block[i] & 0x0F;
      uint32_t t1 = block[i] >> 4;
      // FIPS 204, Algorithm 15 (`CoefFromHalfByte`). Although both the input
      // and output here are secret, it is OK to leak when we rejected a byte.
      // Individual bytes of the SHAKE-256 stream are (indistiguishable from)
      // independent of each other and the original seed, so leaking information
      // about the rejected bytes does not reveal the input or output.
      uint32_t v;
      if (coefficient_from_nibble_2(t0, &v)) {
        out->c[done++] = v;
      }
      if (done < K_DEGREE && coefficient_from_nibble_2(t1, &v)) {
        out->c[done++] = v;
      }
    }
  }

  mbedtls_sha3_free(&shake256_ctxt);
}

// FIPS 204, Algorithm 34 (`ExpandMask`), but just a single step.
static void scalar_sample_mask(scalar_t *out, const uint8_t derived_seed[K_RHO_PRIME_BYTES + 2])
{
  uint8_t buf[640];
  mbedtls_sha3_context shake256_ctxt;
  mbedtls_sha3_init(&shake256_ctxt);
  mbedtls_sha3_starts(&shake256_ctxt, MBEDTLS_SHA3_SHAKE256);
  mbedtls_sha3_update(&shake256_ctxt, derived_seed, K_RHO_PRIME_BYTES + 2);
  mbedtls_sha3_finish(&shake256_ctxt, buf, sizeof(buf));
  mbedtls_sha3_free(&shake256_ctxt);

  scalar_decode_signed_20_19(out, buf);
}

// FIPS 204, Algorithm 29 (`SampleInBall`).
static void scalar_sample_in_ball_vartime(scalar_t *out, const uint8_t *seed, int len)
{
  mbedtls_sha3_context shake256_ctxt;
  mbedtls_sha3_init(&shake256_ctxt);
  mbedtls_sha3_starts(&shake256_ctxt, MBEDTLS_SHA3_SHAKE256);
  mbedtls_sha3_update(&shake256_ctxt, seed, len);

  uint8_t block[136];
  mbedtls_sha3_finish(&shake256_ctxt, block, sizeof(block));

  uint64_t signs = MBEDTLS_GET_UINT64_LE(block, 0);
  int offset = 8;

  // SampleInBall implements a Fisher–Yates shuffle, which unavoidably leaks
  // where the zeros are by memory access pattern. Although this leak happens
  // before bad signatures are rejected, this is safe. See
  // https://boringssl-review.googlesource.com/c/boringssl/+/67747/comment/8d8f01ac_70af3f21/

  memset(out, 0, sizeof(*out));
  for (size_t i = K_DEGREE - TAU; i < K_DEGREE; i++) {
    size_t byte;
    for (;;) {
      if (offset == 136) {
        mbedtls_sha3_finish(&shake256_ctxt, block, sizeof(block));
        offset = 0;
      }

      byte = block[offset++];
      if (byte <= i) {
        break;
      }
    }

    out->c[i] = out->c[byte];
    out->c[byte] = mod_sub(1, 2 * (signs & 1));
    signs >>= 1;
  }

  mbedtls_sha3_free(&shake256_ctxt);
}

// A combination of FIPS 204, Algorithm 32 (`ExpandA`) and matrix multiplication.
static void matrix87_expand_mul(vector8_t *out, const uint8_t rho[K_RHO_BYTES], const vector7_t *a)
{
  uint8_t derived_seed[K_RHO_BYTES + 2];
  memcpy(derived_seed, rho, K_RHO_BYTES);
  vector8_zero(out);
  for (size_t i = 0; i < 8; i++) {
    for (size_t j = 0; j < 7; j++) {
      scalar_t m_ij;
      // Step 1: Generate (i,j)-th matrix entry.
      derived_seed[K_RHO_BYTES + 1] = (uint8_t)i;
      derived_seed[K_RHO_BYTES] = (uint8_t)j;
      scalar_from_keccak_vartime(&m_ij, derived_seed);
      // Step 2: Multiply with right hand side and sum into output.
      scalar_mul_add(&out->v[i], &out->v[i], &m_ij, &a->v[j]);
    }
  }
}

// FIPS 204, Algorithm 33 (`ExpandS`).
static void vectors78_expand_short(vector7_t *s1, vector8_t *s2, const uint8_t sigma[K_SIGMA_BYTES])
{
  uint8_t derived_seed[K_SIGMA_BYTES + 2];
  memcpy(derived_seed, sigma, K_SIGMA_BYTES);
  derived_seed[K_SIGMA_BYTES] = 0;
  derived_seed[K_SIGMA_BYTES + 1] = 0;
  for (size_t i = 0; i < 7; i++) {
    scalar_uniform_2(&s1->v[i], derived_seed);
    ++derived_seed[K_SIGMA_BYTES];
  }
  for (size_t i = 0; i < 8; i++) {
    scalar_uniform_2(&s2->v[i], derived_seed);
    ++derived_seed[K_SIGMA_BYTES];
  }
}

// FIPS 204, Algorithm 34 (`ExpandMask`).
static void vector7_expand_mask(vector7_t *out, const uint8_t seed[K_RHO_PRIME_BYTES], size_t kappa)
{
  uint8_t derived_seed[K_RHO_PRIME_BYTES + 2];
  memcpy(derived_seed, seed, K_RHO_PRIME_BYTES);
  for (size_t i = 0; i < 7; i++) {
    size_t index = kappa + i;
    derived_seed[K_RHO_PRIME_BYTES] = index & 0xFF;
    derived_seed[K_RHO_PRIME_BYTES + 1] = (index >> 8) & 0xFF;
    scalar_sample_mask(&out->v[i], derived_seed);
  }
}

/* Encoding. */

// FIPS 204, Algorithm 16 (`SimpleBitPack`).
static void vector8_encode(uint8_t *out, const vector8_t *a, int bits)
{
  if (bits == 4) {
    for (size_t i = 0; i < 8; i++) {
      scalar_encode_4(out + i * bits * K_DEGREE / 8, &a->v[i]);
    }
  } else {
    for (size_t i = 0; i < 8; i++) {
      scalar_encode_10(out + i * bits * K_DEGREE / 8, &a->v[i]);
    }
  }
}

// FIPS 204, Algorithm 18 (`SimpleBitUnpack`).
static void vector8_decode_10(vector8_t *out, const uint8_t *in)
{
  for (size_t i = 0; i < 8; i++) {
    scalar_decode_10(&out->v[i], in + i * 10 * K_DEGREE / 8);
  }
}

// FIPS 204, Algorithm 17 (`BitPack`).
static void vector7_encode_signed_20_19(uint8_t *out, const vector7_t *a)
{
  for (size_t i = 0; i < 7; i++) {
    scalar_encode_signed_20_19(out + i * 20 * K_DEGREE / 8, &a->v[i]);
  }
}

static void vector7_decode_signed_20_19(vector7_t *out, const uint8_t *in)
{
  for (size_t i = 0; i < 7; i++) {
    scalar_decode_signed_20_19(&out->v[i], in + i * 20 * K_DEGREE / 8);
  }
}

// FIPS 204, Algorithm 28 (`w1Encode`).
static void w1_encode(uint8_t out[128 * 8], const vector8_t *w1)
{
  vector8_encode(out, w1, 4);
}

// FIPS 204, Algorithm 20 (`HintBitPack`).
static void hint_bit_pack(uint8_t out[OMEGA + 8], const vector8_t *h)
{
  memset(out, 0, OMEGA + 8);
  int index = 0;
  for (size_t i = 0; i < 8; i++) {
    for (size_t j = 0; j < K_DEGREE; j++) {
      if (h->v[i].c[j]) {
        // h must have at most OMEGA non-zero coefficients.
        out[index++] = j;
      }
    }
    out[OMEGA + i] = index;
  }
}

// FIPS 204, Algorithm 21 (`HintBitUnpack`).
static int hint_bit_unpack(vector8_t *h, const uint8_t in[OMEGA + 8])
{
  vector8_zero(h);
  int index = 0;
  for (size_t i = 0; i < 8; i++) {
    const int limit = in[OMEGA + i];
    if (limit < index || limit > OMEGA) {
      return 0;
    }
    int last = -1;
    while (index < limit) {
      int byte = in[index++];
      if (last >= 0 && byte <= last) {
        return 0;
      }
      last = byte;
      h->v[i].c[byte] = 1;
    }
  }
  for (; index < OMEGA; index++) {
    if (in[index] != 0) {
      return 0;
    }
  }
  return 1;
}

// FIPS 204, Algorithm 22 (`pkEncode`).
static void encode_public_key(uint8_t out[MLDSA87_PUBLIC_KEY_BYTES], const public_key_t *pub)
{
  memcpy(out, pub->rho, K_RHO_BYTES);
  vector8_encode(&out[K_RHO_BYTES], &pub->t1, 10);
}

// FIPS 204, Algorithm 23 (`pkDecode`).
static void decode_public_key(public_key_t *pub, const uint8_t in[MLDSA87_PUBLIC_KEY_BYTES])
{
  memcpy(pub->rho, in, K_RHO_BYTES);
  vector8_decode_10(&pub->t1, &in[K_RHO_BYTES]);
  // Compute cached public key hash.
  mbedtls_sha3_context shake256_ctxt;
  mbedtls_sha3_init(&shake256_ctxt);
  mbedtls_sha3_starts(&shake256_ctxt, MBEDTLS_SHA3_SHAKE256);
  mbedtls_sha3_update(&shake256_ctxt, in, MLDSA87_PUBLIC_KEY_BYTES);
  mbedtls_sha3_finish(&shake256_ctxt, pub->public_key_hash, sizeof(pub->public_key_hash));
  mbedtls_sha3_free(&shake256_ctxt);
}

// FIPS 204, Algorithm 26 (`sigEncode`).
static void encode_signature(uint8_t out[MLDSA87_SIGNATURE_BYTES], const signature_t *sign)
{
  memcpy(out, sign->c_tilde, 2 * LAMBDA_BYTES);

  uint8_t *z_output = &out[2 * LAMBDA_BYTES];
  vector7_encode_signed_20_19(z_output, &sign->z);

  uint8_t *hint_output = &out[2 * LAMBDA_BYTES + 640 * 7];
  hint_bit_pack(hint_output, &sign->h);
}

// FIPS 204, Algorithm 27 (`sigDecode`).
static int decode_signature(signature_t *sign, const uint8_t in[MLDSA87_SIGNATURE_BYTES])
{
  memcpy(sign->c_tilde, in, 2 * LAMBDA_BYTES);

  const uint8_t *z_input = &in[2 * LAMBDA_BYTES];
  vector7_decode_signed_20_19(&sign->z, z_input);

  const uint8_t *hint_input = &in[2 * LAMBDA_BYTES + 640 * 7];
  return hint_bit_unpack(&sign->h, hint_input);
}

/* Main algorithms. */

// FIPS 204, Algorithm 6 (`ML-DSA.KeyGen_internal`).
static void generate_key_internal(
  uint8_t out_encoded_public_key[MLDSA87_PUBLIC_KEY_BYTES],
  private_key_t *priv,
  const uint8_t entropy[MLDSA87_PRIVATE_SEED_BYTES])
{
  uint8_t augmented_entropy[MLDSA87_PRIVATE_SEED_BYTES + 2];
  memcpy(augmented_entropy, entropy, MLDSA87_PRIVATE_SEED_BYTES);
  // The K and L parameters are appended to the seed.
  augmented_entropy[MLDSA87_PRIVATE_SEED_BYTES] = 8;
  augmented_entropy[MLDSA87_PRIVATE_SEED_BYTES + 1] = 7;

  uint8_t expanded_seed[K_RHO_BYTES + K_SIGMA_BYTES + K_K_BYTES];
  mbedtls_sha3_context shake256_ctxt;
  mbedtls_sha3_init(&shake256_ctxt);
  mbedtls_sha3_starts(&shake256_ctxt, MBEDTLS_SHA3_SHAKE256);
  mbedtls_sha3_update(&shake256_ctxt, augmented_entropy, sizeof(augmented_entropy));
  mbedtls_sha3_finish(&shake256_ctxt, expanded_seed, sizeof(expanded_seed));
  mbedtls_sha3_free(&shake256_ctxt);

  const uint8_t *const rho = expanded_seed;
  const uint8_t *const sigma = expanded_seed + K_RHO_BYTES;
  const uint8_t *const k = expanded_seed + K_RHO_BYTES + K_SIGMA_BYTES;

  // rho is public.
  public_key_t pub;
  memcpy(pub.rho, rho, sizeof(pub.rho));
  memcpy(priv->rho, rho, sizeof(priv->rho));
  memcpy(priv->k, k, sizeof(priv->k));

  vectors78_expand_short(&priv->s1_ntt, &priv->s2_ntt, sigma);
  vector7_ntt(&priv->s1_ntt);

  vector8_t t;
  matrix87_expand_mul(&t, rho, &priv->s1_ntt);
  vector8_inverse_ntt(&t);
  // Here s2 is not in NTT form yet.
  vector8_add(&t, &t, &priv->s2_ntt);

  vector8_power2_round(&pub.t1, &priv->t0_ntt, &t);

  // Convert remaining vectors to NTT form.
  vector8_ntt(&priv->s2_ntt);
  vector8_ntt(&priv->t0_ntt);

  encode_public_key(out_encoded_public_key, &pub);

  mbedtls_sha3_init(&shake256_ctxt);
  mbedtls_sha3_starts(&shake256_ctxt, MBEDTLS_SHA3_SHAKE256);
  mbedtls_sha3_update(&shake256_ctxt, out_encoded_public_key, MLDSA87_PUBLIC_KEY_BYTES);
  mbedtls_sha3_finish(&shake256_ctxt, priv->public_key_hash, sizeof(priv->public_key_hash));
  mbedtls_sha3_free(&shake256_ctxt);
}

static void generate_priv_internal(private_key_t *priv,
  const uint8_t private_key_seed[MLDSA87_PRIVATE_SEED_BYTES])
{
  uint8_t encoded_public_key[MLDSA87_PUBLIC_KEY_BYTES];
  generate_key_internal(encoded_public_key, priv, private_key_seed);
}

// FIPS 204, Algorithm 7 (`ML-DSA.Sign_internal`).
static void sign_internal(
  uint8_t out_encoded_signature[MLDSA87_SIGNATURE_BYTES],
  const private_key_t *priv, const uint8_t *msg, size_t msg_len,
  const uint8_t *context, size_t context_len,
  const uint8_t randomizer[MLDSA87_RANDOMIZER_BYTES])
{
  uint8_t mu[K_MU_BYTES];
  mbedtls_sha3_context shake256_ctxt;
  mbedtls_sha3_init(&shake256_ctxt);
  mbedtls_sha3_starts(&shake256_ctxt, MBEDTLS_SHA3_SHAKE256);
  mbedtls_sha3_update(&shake256_ctxt, priv->public_key_hash, sizeof(priv->public_key_hash));
  // We assume that context_len <= 255.
  uint8_t context_prefix[2] = {0, context_len};
  mbedtls_sha3_update(&shake256_ctxt, context_prefix, 2);
  mbedtls_sha3_update(&shake256_ctxt, context, context_len);
  mbedtls_sha3_update(&shake256_ctxt, msg, msg_len);
  mbedtls_sha3_finish(&shake256_ctxt, mu, K_MU_BYTES);
  mbedtls_sha3_free(&shake256_ctxt);

  uint8_t rho_prime[K_RHO_PRIME_BYTES];
  mbedtls_sha3_init(&shake256_ctxt);
  mbedtls_sha3_starts(&shake256_ctxt, MBEDTLS_SHA3_SHAKE256);
  mbedtls_sha3_update(&shake256_ctxt, priv->k, sizeof(priv->k));
  mbedtls_sha3_update(&shake256_ctxt, randomizer, 32);
  mbedtls_sha3_update(&shake256_ctxt, mu, K_MU_BYTES);
  mbedtls_sha3_finish(&shake256_ctxt, rho_prime, K_RHO_PRIME_BYTES);
  mbedtls_sha3_free(&shake256_ctxt);

  signature_t sign;
  vector8_t w1;
  union {
    vector7_t cs1;
    vector8_t cs2;
  } cs;

  // kappa must not exceed 2^16/L. But the probability of it
  // exceeding even 1000 iterations is vanishingly small.
  for (size_t kappa = 0; ; kappa += 7) {
    vector7_t *y_ntt = &sign.z;
    vector7_expand_mask(y_ntt, rho_prime, kappa);
    vector7_ntt(y_ntt);

    vector8_t *w = &sign.h;
    matrix87_expand_mul(w, priv->rho, y_ntt);
    vector8_inverse_ntt(w);

    vector8_high_bits(&w1, w);
    uint8_t w1_encoded[128 * 8];
    w1_encode(w1_encoded, &w1);

    mbedtls_sha3_init(&shake256_ctxt);
    mbedtls_sha3_starts(&shake256_ctxt, MBEDTLS_SHA3_SHAKE256);
    mbedtls_sha3_update(&shake256_ctxt, mu, K_MU_BYTES);
    mbedtls_sha3_update(&shake256_ctxt, w1_encoded, 128 * 8);
    mbedtls_sha3_finish(&shake256_ctxt, sign.c_tilde, 2 * LAMBDA_BYTES);
    mbedtls_sha3_free(&shake256_ctxt);

    scalar_t c_ntt;
    scalar_sample_in_ball_vartime(&c_ntt, sign.c_tilde, sizeof(sign.c_tilde));
    scalar_ntt(&c_ntt);

    vector7_mul_scalar(&cs.cs1, &priv->s1_ntt, &c_ntt);
    vector7_inverse_ntt(&cs.cs1);

    vector7_t *y = &sign.z;
    vector7_expand_mask(y, rho_prime, kappa);
    vector7_add(&sign.z, y, &cs.cs1);

    vector8_mul_scalar(&cs.cs2, &priv->s2_ntt, &c_ntt);
    vector8_inverse_ntt(&cs.cs2);

    vector8_t *r0 = &w1;
    vector8_sub(r0, w, &cs.cs2);
    vector8_low_bits(r0, r0);

    // Leaking the fact that a signature was rejected is fine as the next
    // attempt at a signature will be (indistinguishable from) independent of
    // this one. Note, however, that we additionally leak which of the two
    // branches rejected the signature. Section 5.5 of
    // https://pq-crystals.org/dilithium/data/dilithium-specification-round3.pdf
    // describes this leak as OK. Note we leak less than what is described by
    // the paper; we do not reveal which coefficient violated the bound, and
    // we hide which of the |z_max| or |r0_max| bound failed. See also
    // https://boringssl-review.googlesource.com/c/boringssl/+/67747/comment/2bbab0fa_d241d35a/
    uint32_t z_max = vector7_max(&sign.z);
    uint32_t r0_max = vector8_max_signed(r0);
    if (mbedtls_ct_uint_ge(z_max, GAMMA1 - BETA) |
        mbedtls_ct_uint_ge(r0_max, K_GAMMA_2 - BETA)) {
      continue;
    }

    vector8_t *ct0 = &w1;
    vector8_mul_scalar(ct0, &priv->t0_ntt, &c_ntt);
    vector8_inverse_ntt(ct0);
    vector8_make_hint(&sign.h, ct0, &cs.cs2, w);

    // See above.
    uint32_t ct0_max = vector8_max(ct0);
    size_t h_ones = vector8_count_ones(&sign.h);
    if (mbedtls_ct_uint_ge(ct0_max, K_GAMMA_2) |
        mbedtls_ct_uint_lt(OMEGA, h_ones)) {
      continue;
    }

    encode_signature(out_encoded_signature, &sign);

    return;
  }
}

// FIPS 204, Algorithm 8 (`ML-DSA.Verify_internal`).
static int verify_internal(const public_key_t *pub,
  const uint8_t encoded_signature[MLDSA87_SIGNATURE_BYTES], const uint8_t *msg,
  size_t msg_len, const uint8_t *context, size_t context_len)
{
  signature_t sign;
  vector8_t az_ntt;
  vector8_t ct1_ntt;

  if (!decode_signature(&sign, encoded_signature))
    return 0;

  // Compute ||z||_\infty and set z = NTT(z).
  uint32_t z_max = vector7_max(&sign.z);
  vector7_ntt(&sign.z);

  uint8_t mu[K_MU_BYTES];
  mbedtls_sha3_context shake256_ctxt;
  mbedtls_sha3_init(&shake256_ctxt);
  mbedtls_sha3_starts(&shake256_ctxt, MBEDTLS_SHA3_SHAKE256);
  mbedtls_sha3_update(&shake256_ctxt, pub->public_key_hash,
                          sizeof(pub->public_key_hash));
  // We assume that context_len <= 255.
  uint8_t context_prefix[2] = {0, context_len};
  mbedtls_sha3_update(&shake256_ctxt, context_prefix, 2);
  mbedtls_sha3_update(&shake256_ctxt, context, context_len);
  mbedtls_sha3_update(&shake256_ctxt, msg, msg_len);
  mbedtls_sha3_finish(&shake256_ctxt, mu, K_MU_BYTES);
  mbedtls_sha3_free(&shake256_ctxt);

  scalar_t c_ntt;
  scalar_sample_in_ball_vartime(&c_ntt, sign.c_tilde, sizeof(sign.c_tilde));
  scalar_ntt(&c_ntt);

  matrix87_expand_mul(&az_ntt, pub->rho, &sign.z);

  vector8_scale_power2_round(&ct1_ntt, &pub->t1);
  vector8_ntt(&ct1_ntt);

  vector8_mul_scalar(&ct1_ntt, &ct1_ntt, &c_ntt);

  vector8_t *w1 = &az_ntt;
  vector8_sub(w1, &az_ntt, &ct1_ntt);
  vector8_inverse_ntt(w1);

  vector8_use_hint(w1, &sign.h, w1);
  uint8_t w1_encoded[128 * 8];
  w1_encode(w1_encoded, w1);

  uint8_t c_tilde[2 * LAMBDA_BYTES];
  mbedtls_sha3_init(&shake256_ctxt);
  mbedtls_sha3_starts(&shake256_ctxt, MBEDTLS_SHA3_SHAKE256);
  mbedtls_sha3_update(&shake256_ctxt, mu, K_MU_BYTES);
  mbedtls_sha3_update(&shake256_ctxt, w1_encoded, 128 * 8);
  mbedtls_sha3_finish(&shake256_ctxt, c_tilde, 2 * LAMBDA_BYTES);
  mbedtls_sha3_free(&shake256_ctxt);

  return z_max < (uint32_t)(GAMMA1 - BETA) && memcmp(c_tilde, sign.c_tilde, 2 * LAMBDA_BYTES) == 0;
}

/* Public API. */

void mldsa87_pub_from_seed(
  uint8_t out_encoded_public_key[MLDSA87_PUBLIC_KEY_BYTES],
  const uint8_t private_key_seed[MLDSA87_PRIVATE_SEED_BYTES])
{
  private_key_t priv;
  generate_key_internal(out_encoded_public_key, &priv, private_key_seed);
}

void mldsa87_sign(
  uint8_t out_encoded_signature[MLDSA87_SIGNATURE_BYTES],
  const uint8_t private_key_seed[MLDSA87_PRIVATE_SEED_BYTES],
  const uint8_t randomizer[MLDSA87_RANDOMIZER_BYTES],
  const uint8_t *msg, size_t msg_len)
{
  private_key_t priv;
  generate_priv_internal(&priv, private_key_seed);
  sign_internal(out_encoded_signature, &priv, msg, msg_len, NULL, 0, randomizer);
}

void mldsa87_sign_deterministic(
  uint8_t out_encoded_signature[MLDSA87_SIGNATURE_BYTES],
  const uint8_t private_key_seed[MLDSA87_PRIVATE_SEED_BYTES],
  const uint8_t *msg, size_t msg_len)
{
  private_key_t priv;
  generate_priv_internal(&priv, private_key_seed);
  uint8_t randomizer[MLDSA87_RANDOMIZER_BYTES];
  memset(randomizer, 0, MLDSA87_RANDOMIZER_BYTES);
  sign_internal(out_encoded_signature, &priv, msg, msg_len, NULL, 0, randomizer);
}

int mldsa87_verify(const uint8_t encoded_public_key[MLDSA87_PUBLIC_KEY_BYTES],
  const uint8_t encoded_signature[MLDSA87_SIGNATURE_BYTES], const uint8_t *msg,
  size_t msg_len)
{
  public_key_t pub;
  decode_public_key(&pub, encoded_public_key);
  return verify_internal(&pub, encoded_signature, msg, msg_len, NULL, 0);
}

#endif /* MBEDTLS_MLDSA_C */
