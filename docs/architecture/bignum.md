# Bignum Design

The goal of the Bignum module in Mbed TLS is to support arithmetic in cryptographic computations like RSA or ECC. Currently, the module does more than it is required to achieve this goal. Representing and handling negative numbers, dynamic sizing and memory allocations for example are not necessary and only add complexity and costs in memory, performance and maintenance.

We are going to introduce an internal interface, that avoids this additional complexity and lays the ground for performance optimizations and further improvements. At first we are going to change how the ECC modules (ECP, ECDSA, ECDH, ECJPAKE) use Bignum. RSA and DHM are out of scope for now.

This document only answers a couple of high level questions, but leaves many of them regarding the details open. Discussing and answering these is left to the PR review process.

## Abstract Approach

All we need from Bignum in ECC is modular arithmetic modulo some fixed large primes. The main structure represents a residue class modulo a given modulus. The operations are performed with respect to this modulus. If there are several operands, the operations make only sense if the modulus is the same for all of them. Furthermore, since we are focusing on ECC for now, we can assume that the modulus is odd.

## Parameter Checking

Pre and post conditions:

- The operands and the result are represented by the least non-negative residue
- The operands and the result all have the same modulus
- The allocated length of the operands and the result is large enough to store the largest element with respect to their modulus
- The operands and the result are not reallocated
- The modulus is odd

Prototyping shows, that tracking and checking these programatically in the ECP module is prohibitively expensive in terms of code size. In the other ECC modules we are going to add minimal checking to safeguard against buffer overflows (we might consider extending this at some later time, but this is out of scope for now). This means that it is the responsibility of the caller module to ensure that these preconditions hold, by calling the life cycle functions as intended and making sure that the moduli are aligned.

(In the ECP module this might allow removing return value checks for certain functions leading to more code size gains, but this too is out of scope for now.)

## Internal API

### Arithmetic Operations

```C
typedef struct
{
    size_t n;
    mbedtls_mpi_uint *p;
} mbedtls_mpi_mod_residue;
```

The main structure will only hold the information necessary to access the value and to do the most minimalistic checks. (As mentioned above not all functions will perform even these minimalistic checks.)

This structure never owns the memory where the limbs are stored, it is allocated and managed by the caller.

```C
typedef struct {
    mbedtls_mpi_uint *p;
    size_t n; // number of limbs
    size_t plen; // bitlen of p
    char srep; // selector to signal the active member of the union
    union rep
    {
        mbedtls_mpi_mont_struct mont;
        mbedtls_mpi_opt_red_struct ored;
    };
    mbedtls_mpi_uint *mempool; // temporary space (2*n limbs or more)
} mbedtls_mpi_mod_modulus;
```

The modulus structure will hold the representation of the modulus, a memory pool for storing temporary values and information for modulus specific computation.

```C
int mbedtls_mpi_mod_reduce( mbedtls_mpi_mod_residue *X, mbedtls_mpi_uint *A,
                            size_t n, mbedtls_mpi_mod_modulus *N )

int mbedtls_mpi_mod_mul( mbedtls_mpi_mod_residue *X, mbedtls_mpi_mod_residue *A,
                         mbedtls_mpi_mod_residue *B, mbedtls_mpi_mod_modulus *N )

int mbedtls_mpi_mod_add( mbedtls_mpi_mod_residue *X, mbedtls_mpi_mod_residue *A,
                         mbedtls_mpi_mod_residue *B, mbedtls_mpi_mod_modulus *N )

int mbedtls_mpi_mod_neg( mbedtls_mpi_mod_residue *X, mbedtls_mpi_mod_residue *A,
                         mbedtls_mpi_mod_modulus *N )

int mbedtls_mpi_mod_sub( mbedtls_mpi_mod_residue *X, mbedtls_mpi_mod_residue *A,
                         mbedtls_mpi_mod_residue *B, mbedtls_mpi_mod_modulus *N )

int mbedtls_mpi_mod_prime_inv( mbedtls_mpi_mod_residue *X,
                               mbedtls_mpi_mod_residue *A,
                               mbedtls_mpi_mod_modulus *P )
```

As mentioned above, there will be a second set of arithmetic functions with the same semantics. This second set of functions will be only used in the ECP module and won't perform any sanity checks on the parameters.

There are several occasions where currently other operations are used, but these can be implemented with the above functions. (For example `mbedtls_mpi_sub_int_mod()` is only ever called on 3 and can be replaced by three calls to `mbedtls_mpi_mod_sub()`.)

### Utility Functions

There are a number of utility functions used throughout the ECC modules:

```C
mbedtls_mpi_get_bit()
mbedtls_mpi_set_bit()
mbedtls_mpi_copy()
mbedtls_mpi_lset()
mbedtls_mpi_cmp_int()
mbedtls_mpi_cmp_mpi()
mbedtls_mpi_safe_cond_assign()
mbedtls_mpi_safe_cond_swap()
mbedtls_mpi_random()
mbedtls_mpi_fill_random()
mbedtls_mpi_size()
mbedtls_mpi_bitlen()
```

For these we need to provide equivalent functionality for the new type while respecting the pre and post conditions described above.

Some of these might not be called directly in the end (for example `mbedtls_mpi_size()` is either used in I/O or can be inferred from the context.)

### Input/Output

We need to provide analogues to the standard input/output functions:

```C
mbedtls_mpi_write_binary_le()
mbedtls_mpi_read_binary_le()
mbedtls_mpi_write_binary()
mbedtls_mpi_read_binary()
```

(`mbedtls_mpi_read_string()` is only ever used in selftest and in a function that is not called from anywhere and therefore can be ignored.)

`derive_mpi` in ECDSA does some form of input as well and will need special considerations when switching to the new type.

## Conversion

Beyond the operations above we will need to convert to and from `mbedtls_mpi` as this is what public facing interfaces use. Since `mbedtls_mpi` and `mbedtls_mpi_mod_residue` use the same limb type, conversion might do copy or aliasing. To keep heap consumption low, we will be providing both and using the most suitable method based on the parameter type.

After we switched to the new API, parameters will be converted to the new types as soon as possible and only converted back when necessary.

### \_ALT Interfaces

Around the `_ALT` interfaces too, we need to convert the parameters to the old types and back to avoid breaking drivers.
