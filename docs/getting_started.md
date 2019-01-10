## Getting started with Mbed Crypto

### What is Mbed Crypto?

Mbed Crypto is an open source cryptographic library that supports a wide range of cryptographic operations, including:
* Key management
* Hashing
* Symmetric cryptography
* Asymmetric cryptography
* Message authentication (MAC)
* Key generation and derivation
* Authenticated encryption with associated data (AEAD)

The Mbed Crypto library is a reference implementation of the cryptography interface of the Arm Platform Security Architecture (PSA). It is written in portable C.

The Mbed Crypto library is distributed under the Apache License, version 2.0.

#### Platform Security Architecture (PSA)

Arm's Platform Security Architecture (PSA) is a holistic set of threat models,
security analyses, hardware and firmware architecture specifications, and an open source firmware reference implementation. PSA provides a recipe, based on industry best practice, that allows security to be consistently designed in, at both a hardware and firmware level. Part of the API provided by PSA is the cryptography interface, which provides access to a set of primitives.

### Using Mbed Crypto

* [Getting the Mbed Crypto library](#getting-the-mbed-crypto-library)
* [Building the Mbed Crypto library](#building-the-mbed-crypto-library)
* [Using the Mbed Crypto library](#using-the-mbed-crypto-library)
* [Importing a key](#importing-a-key)
* [Signing a message using RSA](#signing-a-message-using-RSA)
* [Encrypting or decrypting using symmetric ciphers](#encrypting-or-decrypting-using-symmetric-ciphers)
* [Hashing a message](#hashing-a-message)
* [Deriving a new key from an existing key](#deriving-a-new-key-from-an-existing-key)
* [Generating a random value](#generating-a-random-value)
* [Authenticating and encrypting or decrypting a message](#authenticating-and-encrypting-or-decrypting-a-message)
* [Generating and exporting keys](#generating-and-exporting-keys)
* [More about the Mbed Crypto library](#more-about-the-mbed-crypto-library)

### Getting the Mbed Crypto library

Mbed Crypto releases are available in the [public Github repository]( https://github.com/ARMmbed/mbed-crypto).

### Building the Mbed Crypto library

You need the following tools to build the library with the provided makefiles:
* GNU Make.
* A C toolchain (compiler, linker, archiver).
* Python 2 or Python 3 (either works) to generate the test code.
* Perl to run the tests.

If you have a C compiler such as GCC or Clang, just run `make` in the top-level directory to build the library, a set of unit tests and some sample programs.

To select a different compiler, set the `CC` variable to name or path of the compiler and linker (default: `cc`) and set `AR` to a compatible archiver (default: `ar`), such as:
```
make CC=arm-linux-gnueabi-gcc AR=arm-linux-gnueabi-ar
```
The provided makefiles pass options to the compiler that assume a GCC-like command line syntax. To use a different compiler, you may need to pass different values for `CFLAGS`, `WARNINGS_CFLAGS` and `LDFLAGS`.

To run the unit tests on the host machine, run `make test` from the top-level directory. If you are cross-compiling, copy the test executable from the `tests` directory to the target machine.

### Using the Mbed Crypto library

To use the Mbed Crypto APIs, call `psa_crypto_init()` before calling any other API. This initializes the library.

### Importing a key

To use a key for cryptography operations in Mbed Crypto, you need to first import it into a key slot. Each slot can store only one key at a time. The slot where the key is stored must be unoccupied, and valid for a key of the chosen type.

Prerequisites to importing keys:
* Initialize the library with a successful call to `psa_crypto_init`.

Importing a key and checking key information:
1. Import a key pair into key slot `1`.
1. Test the information stored in this slot:
```C
    int key_slot = 1;
    uint8_t *data = "KEYPAIR_KEY_DATA";
    size_t data_size;
    psa_key_type_t type = PSA_KEY_TYPE_RSA_PUBLIC_KEY;
    size_t got_bits;
    psa_key_type_t got_type;
    size_t expected_bits = data_size;
    psa_key_type_t type = PSA_KEY_TYPE_RAW_DATA;
    size_t export_size = data_size;

    psa_crypto_init();

    /* Import the key */
    status = psa_import_key(key_slot, type, data, data_size);

    /* Test the key information */
    status = psa_get_key_information(slot, &got_type, &got_bits);

    /* Destroy the key */
    psa_destroy_key(key_slot);
    mbedtls_psa_crypto_free();
```

### Signing a message using RSA

Mbed Crypto provides support for encrypting, decrypting, signing and verifying messages using public key signature algorithms (such as RSA or ECDSA).

Prerequisites to working with the asymmetric cipher API:
* Initialize the library with a successful call to `psa_crypto_init`.
* Configure the key policy accordingly:
    * `PSA_KEY_USAGE_SIGN` to allow signing.
    * `PSA_KEY_USAGE_VERIFY` to allow signature verification.
* Have a valid key in the key slot.

To sign a given message `payload` using RSA:
1. Set the key policy of the chosen key slot by calling `psa_key_policy_set_usage()` with the `PSA_KEY_USAGE_SIGN` parameter and the algorithm `PSA_ALG_RSA_PKCS1V15_SIGN_RAW`.
This allows the key in the key slot to be used for RSA signing.
1. Import the key into the key slot by calling `psa_import_key()`. You can use an already imported key instead of importing a new one.
1. Call `psa_asymmetric_sign()` and get the output buffer that contains the signature:
```C
    psa_status_t status;
    int key_slot = 1;
    unsigned char key[] = "RSA_KEY";
    unsigned char payload[] = "ASYMMETRIC_INPUT_FOR_SIGN";
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;
    unsigned char signature[PSA_ASYMMETRIC_SIGNATURE_MAX_SIZE] = {0};
    size_t signature_length;

    status = psa_crypto_init();

    /* Import the key */
    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_SIGN,
                             PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
    status = psa_set_key_policy(key_slot, &policy);

    status = psa_import_key(key_slot, PSA_KEY_TYPE_RSA_KEYPAIR,
                            key, sizeof(key));

    /* Sing message using the key */
    status = psa_asymmetric_sign(key_slot, PSA_ALG_RSA_PKCS1V15_SIGN_RAW,
                                 payload, sizeof(payload),
                                 signature, sizeof(signature),
                                 &signature_length);
    /* Destroy the key */
    psa_destroy_key(key_slot);
    mbedtls_psa_crypto_free();
```

### Encrypting or decrypting using symmetric ciphers

Mbed Crypto provides support for encrypting and decrypting messages using various symmetric cipher algorithms (both block and stream ciphers).

Prerequisites to working with the symmetric cipher API:
* Initialize the library with a successful call to `psa_crypto_init`.
* Configure the key policy accordingly (`PSA_KEY_USAGE_ENCRYPT` to allow encryption or `PSA_KEY_USAGE_DECRYPT` to allow decryption).
* Have a valid key in the key slot.

Encrypting a message with a symmetric cipher:
1. Allocate an operation (`psa_cipher_operation_t`) structure to pass to the cipher functions.
1. Call `psa_cipher_encrypt_setup` to initialize the operation structure and  specify the algorithm and the key to be used.
1. Call either `psa_cipher_generate_iv` or `psa_cipher_set_iv` to generate or set the initialization vector (IV). We recommended `psa_cipher_generate_iv`, unless you require a specific IV value.
1. Call `psa_cipher_update` one or more times, passing either the whole or only a fragment of the message each time.
1. Call `psa_cipher_finish` to end the operation and output the encrypted message.

Encrypting random data using an AES key in cipher block chain (CBC) mode with no padding (assuming all prerequisites have been fulfilled):
```c
    psa_key_slot_t key_slot = 1;
    psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
    psa_cipher_operation_t operation;
    size_t block_size = PSA_BLOCK_CIPHER_BLOCK_SIZE(PSA_KEY_TYPE_AES);
    unsigned char input[block_size];
    unsigned char iv[block_size];
    size_t iv_len;
    unsigned char output[block_size];
    size_t output_len;

    /* generate some random data to be encrypted */
    psa_generate_random(input, sizeof(input));

    /* encrypt the key */
    psa_cipher_encrypt_setup(&operation, key_slot, alg);
    psa_cipher_generate_iv(&operation, iv, sizeof(iv), &iv_len);
    psa_cipher_update(&operation, input, sizeof(input),
    output, sizeof(output),
    &output_len);
    psa_cipher_finish(&operation,
    output + output_len, sizeof(output) - output_len,
    &output_len);
    /* Clean up cipher operation context */
    psa_cipher_abort(&operation);
```

Decrypting a message with a symmetric cipher:
1. Allocate an operation (`psa_cipher_operation_t`) structure to pass to the cipher functions.
1. Call `psa_cipher_decrypt_setup` to initialize the operation structure and to specify the algorithm and the key to be used.
1. Call `psa_cipher_set_iv` with the IV for the decryption.
1. Call `psa_cipher_update` one or more times passing either the whole or only a fragment of the message each time.
1. Call `psa_cipher_finish` to end the operation and output the decrypted message.

Decrypting encrypted data using an AES key in CBC mode with no padding
(assuming all prerequisites have been fulfilled):
```c
    psa_key_slot_t key_slot = 1;
    psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
    psa_cipher_operation_t operation;
    size_t block_size = PSA_BLOCK_CIPHER_BLOCK_SIZE(PSA_KEY_TYPE_AES);
    unsigned char input[block_size];
    unsigned char iv[block_size];
    size_t iv_len;
    unsigned char output[block_size];
    size_t output_len;

    /* setup input data */
    fetch_iv(iv, sizeof(iv));     /* fetch the IV used when the data was encrypted */
    fetch_input(input, sizeof(input));      /* fetch the data to be decrypted */

    /* encrypt the encrypted data */
    psa_cipher_decrypt_setup(&operation, key_slot, alg);
    psa_cipher_set_iv(&operation, iv, sizeof(iv));
    psa_cipher_update(&operation, input, sizeof(input),
    output, sizeof(output),
    &output_len);
    psa_cipher_finish(&operation,
    output + output_len, sizeof(output) - output_len,
    &output_len);
    /* Clean up cipher operation context */
    psa_cipher_abort(&operation);
```

#### Handling cipher operation contexts

Once you've initialized the operation structure with a successful call to `psa_cipher_encrypt_setup` or `psa_cipher_decrypt_setup`, you can terminate the operation at any time by calling `psa_cipher_abort`.

The call to `psa_cipher_abort` frees any resources associated with the operation (except for the operation structure itself). An implicit call to `psa_cipher_abort` occurs when any of these conditions occur:
* A call to `psa_cipher_generate_iv`, `psa_cipher_set_iv` or `psa_cipher_update` has failed (returning any status other than `PSA_SUCCESS`).
* Either a successful or failed call to `psa_cipher_finish`.

Once `psa_cipher_abort` has been called (either implicitly by the implementation or explicitly by the user), the operation structure is invalidated and may not be reused for the same operation. However, the operation structure may be reused for a different operation by calling either `psa_cipher_encrypt_setup` or `psa_cipher_decrypt_setup` again.

For an operation that has been initialized successfully (by a successful call to `psa_cipher_encrypt_setup` or `psa_cipher_decrypt_setup`) it is imperative that at some time `psa_cipher_abort` is called.

Multiple sequential calls to `psa_cipher_abort` on an operation that has already been terminated (either implicitly or explicitly) are safe and have no effect.

### Hashing a message

Mbed Crypto lets you compute and verify hashes using various hashing algorithms.

The current implementation supports the following hash algorithms: `MD2`, `MD4`, `MD5`, `RIPEMD160`, `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, and `SHA-512`.

Prerequisites to working with the hash APIs:
* Initialize the library with a successful call to `psa_crypto_init`.

To calculate a hash:
1. Allocate an operation structure (`psa_hash_operation_t`) to pass to the hash functions.
1. Call `psa_hash_setup` to initialize the operation structure and specify the hash algorithm.
1. Call `psa_hash_update` one or more times, passing either the whole or only a fragment of the message each time.
1. Call `psa_hash_finish` to calculate the hash, or `psa_hash_verify` to compare the computed hash with an expected hash value.

Calculate the `SHA-256` hash of a message:
```c
    psa_algorithm_t alg = PSA_ALG_SHA_256;
    psa_hash_operation_t operation;
    unsigned char input[] = { 'a', 'b', 'c' };
    unsigned char actual_hash[PSA_HASH_MAX_SIZE];
    size_t actual_hash_len;

    /* Compute hash of message  */
    psa_hash_setup(&operation, alg);
    psa_hash_update(&operation, input, sizeof(input));
    psa_hash_finish(&operation, actual_hash, sizeof(actual_hash), &actual_hash_len);

    /* Clean up hash operation context */
    psa_hash_abort(&operation);
```

Verify the `SHA-256` hash of a message:
```c
    psa_algorithm_t alg = PSA_ALG_SHA_256;
    psa_hash_operation_t operation;
    unsigned char input[] = { 'a', 'b', 'c' };
    unsigned char expected_hash[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
        0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    size_t expected_hash_len = PSA_HASH_SIZE(alg);

    /* Verify message hash */
    psa_hash_setup(&operation, alg);
    psa_hash_update(&operation, input, sizeof(input));
    psa_hash_verify(&operation, expected_hash, expected_hash_len);
```

The API provides the macro `PSA_HASH_SIZE`, which returns the expected hash length (in bytes) for the specified algorithm.

#### Handling hash operation contexts

Once the operation structure has been successfully initialized by a successful call to `psa_hash_setup`, it's possible to terminate the operation at any time by calling `psa_hash_abort`. The call to `psa_hash_abort` frees any resources associated with the operation (except for the operation structure itself).

An implicit call to `psa_hash_abort` occurs when any of these conditions occur:
1. A call to `psa_hash_update` has failed (returning any status other than `PSA_SUCCESS`).
1. Either a successful or failed call to `psa_hash_finish`.
1. Either a successful or failed call to `psa_hash_verify`.

Once `psa_hash_abort` has been called (either implicitly by the implementation or explicitly by the user), the operation structure is invalidated and may not be reused for the same operation. However, the operation structure may be reused for a different operation by calling `psa_hash_setup` again.

For an operation that has been initialized successfully (by a successful call to `psa_hash_setup`) it is imperative that at some time `psa_hash_abort` is called.

Multiple sequential calls to `psa_hash_abort` on an operation that has already been terminated (either implicitly or explicitly) is safe and has no effect.

### Generating a random value

Mbed Crypto can generate random data.

Prerequisites to random generation:
* Initialize the library with a successful call to `psa_crypto_init`.

Generate a random, ten-byte piece of data:
1. Generate random bytes by calling `psa_generate_random()`:
```C
    psa_status_t status;
    uint8_t random[10] = { 0 };
    psa_crypto_init();
    status = psa_generate_random(random, sizeof(random));

    mbedtls_psa_crypto_free();
```

### Deriving a new key from an existing key

Mbed Crypto provides a key derivation API that lets you derive new keys from existing ones. Key derivation is based upon the generator abstraction. A generator must first be initialized and set up (provided with a key and optionally other data) and then derived data can be read from it either to a buffer or directly imported into a key slot.

Prerequisites to working with the key derivation APIs:
* Initialize the library with a successful call to `psa_crypto_init`.
* Configure the key policy for the key used for derivation (`PSA_KEY_USAGE_DERIVE`)
* The key type must be `PSA_KEY_TYPE_DERIVE`.

Deriving a new AES-CTR 128-bit encryption key into a given key slot using HKDF with a given key, salt and label:
1. Set the key policy for key derivation by calling `psa_key_policy_set_usage()` with `PSA_KEY_USAGE_DERIVE` parameter, and the algorithm `PSA_ALG_HKDF(PSA_ALG_SHA_256)`.
1. Import the key into the key slot by calling `psa_import_key()`. You can skip this step and the previous one if the key has already been imported into a known key slot.
1. Set up the generator using the `psa_key_derivation` function providing a key slot containing a key that can be used for key derivation and a salt and label (Note: salt and label are optional).
1. Initiate a key policy to for the derived key by calling `psa_key_policy_set_usage()` with `PSA_KEY_USAGE_ENCRYPT` parameter and the algorithm `PSA_ALG_CTR`.
1. Set the key policy to the derived key slot.
1. Import a key from generator into the desired key slot using (`psa_generator_import_key`).
1. Clean up generator.

At this point the derived key slot holds a new 128-bit AES-CTR encryption key derived from the key, salt and label provided:
```C
    psa_key_slot_t base_key = 1;
    psa_key_slot_t derived_key = 2;
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;

    unsigned char key[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b };

    unsigned char salt[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                             0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };

    unsigned char label[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
                              0xf7, 0xf8, 0xf9 };

    psa_algorithm_t alg = PSA_ALG_HKDF(PSA_ALG_SHA_256);
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;
    psa_crypto_generator_t generator = PSA_CRYPTO_GENERATOR_INIT;
    size_t derived_bits = 128;
    size_t capacity = PSA_BITS_TO_BYTES(derived_bits);

    status = psa_crypto_init();

    /* Import a key for use in key derivation, if such a key has already been imported you can skip this part */
    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_DERIVE, alg);
    status = psa_set_key_policy(base_key, &policy);

    status = psa_import_key(base_key, PSA_KEY_TYPE_DERIVE, key, sizeof(key));

    /* Derive a key into a key slot*/
    status = psa_key_derivation(&generator, base_key, alg, salt, sizeof(salt),
                                label, sizeof(label), capacity);

    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_ENCRYPT, PSA_ALG_CTR);

    psa_set_key_policy(derived_key, &policy);

    psa_generator_import_key(derived_key, PSA_KEY_TYPE_AES, derived_bits, &generator);

    /* Clean up generator and key */
    psa_generator_abort(&generator);
    /* as part of clean up you may want to clean up the keys used by calling:
     * psa_destroy_key( base_key ); or psa_destroy_key( derived_key ); */
    mbedtls_psa_crypto_free();
```

### Authenticating and encrypting or decrypting a message

Mbed Crypto provides a simple way for authenticate and encrypt with associated data (AEAD) supporting `PSA_ALG_CCM` algorithm.

Prerequisites to working with the AEAD ciphers APIs:
* Initialize the library with a successful call to `psa_crypto_init`.
* The key policy for the key used for derivation must be configured accordingly (`PSA_KEY_USAGE_ENCRYPT` or `PSA_KEY_USAGE_DECRYPT`).

To authenticate and encrypt a message:
```C
    int slot = 1;
    psa_status_t status;
    unsigned char key[] = { 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
                            0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF };

    unsigned char nonce[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0A, 0x0B };

    unsigned char additional_data[] = { 0xEC, 0x46, 0xBB, 0x63, 0xB0, 0x25, 0x20,
                                        0xC3, 0x3C, 0x49, 0xFD, 0x70 };

    unsigned char input_data[] = { 0xB9, 0x6B, 0x49, 0xE2, 0x1D, 0x62, 0x17, 0x41,
                                   0x63, 0x28, 0x75, 0xDB, 0x7F, 0x6C, 0x92, 0x43,
                                   0xD2, 0xD7, 0xC2 };
    unsigned char *output_data = NULL;
    size_t output_size = 0;
    size_t output_length = 0;
    size_t tag_length = 16;
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;

    output_size = sizeof(input_data) + tag_length;
    output_data = malloc(output_size);
    status = psa_crypto_init();

    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_ENCRYPT, PSA_ALG_CCM);
    status = psa_set_key_policy(slot, &policy);

    status = psa_import_key(slot, PSA_KEY_TYPE_AES, key, sizeof(key));

    status = psa_aead_encrypt(slot, PSA_ALG_CCM,
                              nonce, sizeof(nonce),
                              additional_data, sizeof(additional_data),
                              input_data, sizeof(input_data),
                              output_data, output_size,
                              &output_length);

    psa_destroy_key(slot);
    mbedtls_free(output_data);
    mbedtls_psa_crypto_free();
```

To authenticate and decrypt a message:

```C
    int slot = 1;
    psa_status_t status;
    unsigned char key[] = {
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
        0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF
    };

    unsigned char nonce[] = { 0xEC, 0x46, 0xBB, 0x63, 0xB0, 0x25, 0x20, 0xC3,
                              0x3C, 0x49, 0xFD, 0x70
                            };

    unsigned char additional_data[] = { 0xEC, 0x46, 0xBB, 0x63, 0xB0, 0x25, 0x20,
                                        0xC3, 0x3C, 0x49, 0xFD, 0x70
                                      };
    unsigned char input_data[] = { 0xB9, 0x6B, 0x49, 0xE2, 0x1D, 0x62, 0x17, 0x41,
                                   0x63, 0x28, 0x75, 0xDB, 0x7F, 0x6C, 0x92, 0x43,
                                   0xD2, 0xD7, 0xC2
                                 };
    unsigned char *output_data = NULL;
    size_t output_size = 0;
    size_t output_length = 0;
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;

    output_size = sizeof(input_data);
    output_data = malloc(output_size);
    status = psa_crypto_init();

    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_DECRYPT, PSA_ALG_CCM);
    status = psa_set_key_policy(slot, &policy);

    status = psa_import_key(slot, PSA_KEY_TYPE_AES, key, sizeof(key));

    status = psa_aead_decrypt(slot, PSA_ALG_CCM,
                              nonce, sizeof(nonce),
                              additional_data, sizeof(additional_data),
                              input_data, sizeof(input_data),
                              output_data, output_size,
                              &output_length);

    psa_destroy_key(slot);
    mbedtls_free(output_data);
    mbedtls_psa_crypto_free();
```

### Generating and exporting keys

Mbed Crypto provides a simple way to generate a key or key pair.

Prerequisites to using key generation and export APIs:
* Initialize the library with a successful call to `psa_crypto_init`.

Generate a piece of random 128-bit AES data:
1. Set the key policy for key generation by calling `psa_key_policy_set_usage()` with the `PSA_KEY_USAGE_EXPORT` parameter and the algorithm `PSA_ALG_GCM`.
1. Generate a random AES key by calling `psa_generate_key()`.
1. Export the generated key by calling `psa_export_key()`:
```C
    int slot = 1;
    size_t bits = 128;
    size_t exported_size = bits;
    size_t exported_length = 0;
    uint8_t *exported = malloc(exported_size);
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;

    psa_crypto_init();

    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_EXPORT, PSA_ALG_GCM);
    psa_set_key_policy(slot, &policy);

    /* Generate a key */
    psa_generate_key(slot, PSA_KEY_TYPE_AES, bits, NULL, 0);

    psa_export_key(slot, exported, exported_size, &exported_length)

    psa_destroy_key(slot);
    mbedtls_psa_crypto_free();
```

### More about the Mbed Crypto library

More information on [Mbed Crypto](https://github.com/ARMmbed/mbed-crypto/).

More information on [PSA Crypto](https://github.com/ARMmbed/mbed-crypto/blob/development/docs/PSA_Crypto_API_Overview.pdf).
