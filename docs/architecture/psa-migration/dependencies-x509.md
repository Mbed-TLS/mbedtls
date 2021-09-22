Dependencies of the X.509 library on the Crypto library
=======================================================

This document is part of the technical study on how to port Mbed TLS to PSA
Crypto. It describes the dependencies of libmbedx509.a on libmbedcrypto.a.

More precisely, it describes what functions from libmbedcrypto.a are called
from libmbedx509.a - other forms of dependencies such as using static inline
functions or types, accessing private struct members, etc., are not listed.

It is based on Mbed TLS 3.0, excluding support for restartble ECP operations.

Non-Crypto dependencies
-----------------------

The X.509 library has a number of dependencies on libmbedcrypto.a that are not
cryptographic, hence are unlikely to be covered by the PSA Crypto API.

These involve the following modules:

- asn1
- oid
- pem
- platform
- threading

Crypto dependencies (high-level)
--------------------------------

The X.509 library depends on the following cryptographic modules:

- pk
- md
- mpi
- sha1

More specifically, calls are made to the following API functions:

```
mbedtls_pk_can_do
mbedtls_pk_free
mbedtls_pk_get_bitlen
mbedtls_pk_get_name
mbedtls_pk_get_type
mbedtls_pk_load_file
mbedtls_pk_parse_subpubkey
mbedtls_pk_sign
mbedtls_pk_verify_ext
mbedtls_pk_write_pubkey
mbedtls_pk_write_pubkey_der

mbedtls_md
mbedtls_md_get_name
mbedtls_md_get_size
mbedtls_md_info_from_type

mbedtls_mpi_copy
mbedtls_mpi_free
mbedtls_mpi_init

mbedtls_sha1
```

Note: the dependency on MPI is because the certificate's serial number is
stored as an MPI in `struct mbedtls_x509write_cert` - the MPI is used purely
as a container for bytes. The depencency is embedded in the public API as
`mbedtls_x509write_crt_set_serial` take an argument of type `mbedtls_mpi *`.

Note: the direct dependency on SHA1 is in `x509write_crt.c` and makes sense
because it's the only hash that can be used to compute key identifiers for the
Subject Key Identifier and Authority Key Identifier extensions. Replacing that
with an algorithm-agnistic API would or course be easy.

File by file analysis
---------------------

The X.509 library consists of the following C files and associated headers:
```
x509.c
x509_create.c
x509_crl.c
x509_crt.c
x509_csr.c
x509write_crt.c
x509write_csr.c
```

### `x509.c`

- In `mbedtls_x509_sig_alg_gets()`
  call `mbedtls_md_info_from_type()` and `mbedtls_md_get_name()`
  to print out information

### `x509_crl.c`

- In `mbedtls_x509_crl_parse_file()`
  call `mbedtls_pk_load_file()`
  to load files if `MBEDTLS_FS_IO` defined

### `x509_crt.c`

**Note:** All calls to PK APIs in this file use public (not private) keys.

- In `x509_profile_check_key()`
  call `mbedtls_pk_get_type()` and `mbedtls_pk_get_bitlen()`

- In `x509_profile_check_key()`
  call `mbedtls_pk_ec()`
  to get the group id

- In `x509_crt_parse_der_core()`
  call `mbedtls_pk_parse_subpubkey()`

- In `mbedtls_x509_crt_parse_file()`
  call `mbedtls_pk_load_file()`
  to load files if `MBEDTLS_FS_IO` defined

- In `mbedtls_x509_crt_info()`
  call `mbedtls_pk_get_name()` and `mbedtls_pk_get_bitlen()`
  to print out information

- In `x509_crt_verifycrl()`
  call `mbedtls_md_info_from_type()`, `mbedtls_md()`, `mbedtls_pk_verify_ext()` and `mbedtls_md_get_size()`
  to verify CRL signature

- In `x509_crt_check_signature()`
  call `mbedtls_md_info_from_type()`, `mbedtls_md_get_size()`, `mbedtls_md()`, then `mbedtls_pk_can_do()` and `mbedtls_pk_verify_ext()`
  to verify certificate signature

- In `x509_crt_verify_restartable_ca_cb()`
  call `mbedtls_pk_get_type()`
  to check against profile

- In `mbedtls_x509_crt_free()`
  call `mbedtls_pk_free()`

### `x509_csr.c`

**Note:** All calls to PK APIs in this file use public (not private) keys.

- In `mbedtls_x509_csr_parse_der()`
  call `mbedtls_pk_parse_subpubkey()`

- In `mbedtls_x509_csr_parse_file()`
  call `mbedtls_pk_load_file()`
  to load files if `MBEDTLS_FS_IO` defined

- In `mbedtls_x509_csr_info()`
  call `mbedtls_pk_get_name()` and `mbedtls_pk_get_bitlen()`
  to print out information

- In `mbedtls_x509_csr_free()`
  call `mbedtls_pk_free()`

### `x509_create.c`

No call to crypto functions - mostly ASN.1 writing and data conversion.

### `x509write_crt.c`

**Note:** Calls to PK APIs in this file are both on public and private keys.

- In `mbedtls_x509write_crt_init()`, resp. `mbedtls_x509write_crt_free()`
  call `mbedtls_mpi_init()`, resp. `mbedtls_mpi_free()`
  to manage the serial number

- In `mbedtls_x509write_crt_set_serial()`
  call `mbedtls_mpi_copy()`

- In `mbedtls_x509write_crt_set_subject_key_identifier()` and `mbedtls_x509write_crt_set_authority_key_identifier()`
  call `mbedtls_pk_write_pubkey()` and `mbedtls_sha1_ret()`

- In `mbedtls_x509write_crt_der()`
  call `mbedtls_pk_can_do()`
  on a private key (issuer)
  to write out correct signature algorithm

- In `mbedtls_x509write_crt_der()`
  call `mbedtls_pk_write_pubkey_der()`
  on a public key (subject)

- In `mbedtls_x509write_crt_der()`
  call `mbedtls_md_info_from_type()` and `mbedtls_md()`
  to prepare for signing

- In `mbedtls_x509write_crt_der()`
  call `mbedtls_pk_sign()`
  on a private key (issuer)
  to sign certificate being issued

### `x509write_csr.c`

**Note:** All calls for PK APIs in this file are on private (not public) keys

- In `mbedtls_x509write_csr_der()`
  call `mbedtls_pk_write_pubkey_der()`

- In `mbedtls_x509write_csr_der()`
  call `mbedtls_md_info_from_type()` and `mbedtls_md()`

- In `mbedtls_x509write_csr_der()`
  call `mbedtls_pk_sign()`

- Call `mbedtls_pk_can_do()`
  on a private key (writer's)
  to write out correct signature algorithm
