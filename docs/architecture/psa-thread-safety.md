Thread safety of the PSA subsystem
==================================

## Requirements

### Backward compatibility requirement

Code that is currently working must keep working. There can be an exception for code that uses features that are advertised as experimental; for example, it would be annoying but ok to add extra requirements for drivers.

(In this section, “currently” means Mbed TLS releases without proper concurrency management: 3.0.0, 3.1.0, and any other subsequent 3.x version.)

In particular, if you either protect all PSA calls with a mutex, or only ever call PSA functions from a single thread, your application currently works and must keep working. If your application currently builds and works with `MBEDTLS_PSA_CRYPTO_C` and `MBEDTLS_THREADING_C` enabled, it must keep building and working.

As a consequence, we must not add a new platform requirement beyond mutexes for the base case. It would be ok to add new platform requirements if they're only needed for PSA drivers, or if they're only performance improvements.

Tempting platform requirements that we cannot add to the default `MBEDTLS_THREADING_C` include:

* Releasing a mutex from a different thread than the one that acquired it. This isn't even guaranteed to work with pthreads.
* New primitives such as semaphores or condition variables.

### Correctness out of the box

If you build with `MBEDTLS_PSA_CRYPTO_C` and `MBEDTLS_THREADING_C`, the code must be functionally correct: no race conditions, deadlocks or livelocks.

The [PSA Crypto API specification](https://armmbed.github.io/mbed-crypto/html/overview/conventions.html#concurrent-calls) defines minimum expectations for concurrent calls. They must work as if they had been executed one at a time, except that the following cases have undefined behavior:

* Destroying a key while it's in use.
* Concurrent calls using the same operation object. (An operation object may not be used by more than one thread at a time. But it can move from one thread to another between calls.)
* Overlap of an output buffer with an input or output of a concurrent call.
* Modification of an input buffer during a call.

Note that while the specification does not define the behavior in such cases, Mbed TLS can be used as a crypto service. It's acceptable if an application can mess itself up, but it is not acceptable if an application can mess up the crypto service. As a consequence, destroying a key while it's in use may violate the security property that all key material is erased as soon as `psa_destroy_key` returns, but it may not cause data corruption or read-after-free inside the key store.

### No spinning

The code must not spin on a potentially non-blocking task. For example, this is proscribed:
```
lock(m);
while (!its_my_turn) {
    unlock(m);
    lock(m);
}
```

Rationale: this can cause battery drain, and can even be a livelock (spinning forever), e.g. if the thread that might unblock this one has a lower priority.

### Driver requirements

At the time of writing, the driver interface specification does not consider multithreaded environments.

We need to define clear policies so that driver implementers know what to expect. Here are two possible policies at two ends of the spectrum; what is desirable is probably somewhere in between.

* Driver entry points may be called concurrently from multiple threads, even if they're using the same key, and even including destroying a key while an operation is in progress on it.
* At most one driver entry point is active at any given time.

A more reasonable policy could be:

* By default, each driver only has at most one entry point active at any given time. In other words, each driver has its own exclusive lock.
* Drivers have an optional `"thread_safe"` boolean property. If true, it allows concurrent calls to this driver.
* Even with a thread-safe driver, the core never starts the destruction of a key while there are operations in progress on it, and never performs concurrent calls on the same multipart operation.

### Long-term performance requirements

In the short term, correctness is the important thing. We can start with a global lock.

In the medium to long term, performing a slow or blocking operation (for example, a driver call, or an RSA decryption) should not block other threads, even if they're calling the same driver or using the same key object.

We may want to go directly to a more sophisticated approach because when a system works with a global lock, it's typically hard to get rid of it to get more fine-grained concurrency.

### Key destruction long-term requirements

As noted above in [“Correctness out of the box”](#correctness-out-of-the-box), when a key is destroyed, it's ok if `psa_destroy_key` allows copies of the key to live until ongoing operations using the key return. In the long term, it would be good to guarantee that `psa_destroy_key` wipes all copies of the key material.

#### Summary of guarantees when `psa_destroy_key` returns

* The key identifier doesn't exist. Rationale: this is a functional requirement for persistent keys: the caller can immediately create a new key with the same identifier.
* The resources from the key have been freed. Rationale: in a low-resource condition, this may be necessary for the caller to re-create a similar key, which should be possible.
* The call must not block indefinitely, and in particular cannot wait for an event that is triggered by application code such as calling an abort function. Rationale: this may not strictly be a functional requirement, but it is an expectation `psa_destroy_key` does not block forever due to another thread, which could potentially be another process on a multi-process system.
* In the long term, no copy of the key material exists. Rationale: this is a security requirement. We do not have this requirement yet, but we need to document this as a security weakness, and we would like to become compliant.

## Resources to protect

Analysis of the behavior of the PSA key store as of Mbed TLS 9202ba37b19d3ea25c8451fd8597fce69eaa6867.

### Global variables

* `psa_crypto_slot_management::global_data.key_slots[i]`: see [“Key slots”](#key-slots).

* `psa_crypto_slot_management::global_data.key_slots_initialized`:
    * `psa_initialize_key_slots`: modification.
    * `psa_wipe_all_key_slots`: modification.
    * `psa_get_empty_key_slot`: read.
    * `psa_get_and_lock_key_slot`: read.

* `psa_crypto::global_data.rng`: depends on the RNG implementation. See [“Random generator”](#random-generator).
    * `psa_generate_random`: query.
    * `mbedtls_psa_crypto_configure_entropy_sources` (only if `MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG` is enabled): setup. Only called from `psa_crypto_init` via `mbedtls_psa_random_init`, or from test code.
    * `mbedtls_psa_crypto_free`: deinit.
    * `psa_crypto_init`: seed (via `mbedtls_psa_random_seed`); setup via `mbedtls_psa_crypto_configure_entropy_sources.

* `psa_crypto::global_data.{initialized,rng_state}`: these are bit-fields and cannot be modified independently so they must be protected by the same mutex. The following functions access these fields:
    * `mbedtls_psa_crypto_configure_entropy_sources` [`rng_state`] (only if `MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG` is enabled): read. Only called from `psa_crypto_init` via `mbedtls_psa_random_init`, or from test code.
    * `mbedtls_psa_crypto_free`: modification.
    * `psa_crypto_init`: modification.
    * Many functions via `GUARD_MODULE_INITIALIZED`: read.

### Key slots

#### Key slot array traversal

“Occupied key slot” is determined by `psa_is_key_slot_occupied` based on `slot->attr.type`.

The following functions traverse the key slot array:

* `psa_get_and_lock_key_slot_in_memory`: reads `slot->attr.id`.
* `psa_get_and_lock_key_slot_in_memory`: calls `psa_lock_key_slot` on one occupied slot.
* `psa_get_empty_key_slot`: calls `psa_is_key_slot_occupied`.
* `psa_get_empty_key_slot`: calls `psa_wipe_key_slot` and more modifications on one occupied slot with no active user.
* `psa_get_empty_key_slot`: calls `psa_lock_key_slot` and more modification on one unoccupied slot.
* `psa_wipe_all_key_slots`: writes to all slots.
* `mbedtls_psa_get_stats`: reads from all slots.

#### Key slot state

The following functions modify a slot's usage state:

* `psa_lock_key_slot`: writes to `slot->lock_count`.
* `psa_unlock_key_slot`: writes to `slot->lock_count`.
* `psa_wipe_key_slot`: writes to `slot->lock_count`.
* `psa_destroy_key`: reads `slot->lock_count`, calls `psa_lock_key_slot`.
* `psa_wipe_all_key_slots`: writes to all slots.
* `psa_get_empty_key_slot`: writes to `slot->lock_count` and calls `psa_wipe_key_slot` and `psa_lock_key_slot` on one occupied slot with no active user; calls `psa_lock_key_slot` on one unoccupied slot.
* `psa_close_key`: reads `slot->lock_count`; calls `psa_get_and_lock_key_slot_in_memory`, `psa_wipe_key_slot` and `psa_unlock_key_slot`.
* `psa_purge_key`: reads `slot->lock_count`; calls `psa_get_and_lock_key_slot_in_memory`, `psa_wipe_key_slot` and `psa_unlock_key_slot`.

**slot->attr access:**
`psa_crypto_core.h`:
* `psa_key_slot_set_flags` - writes to attr.flags
* `psa_key_slot_set_bits_in_flags` - writes to attr.flags
* `psa_key_slot_clear_bits` - writes to attr.flags
* `psa_is_key_slot_occupied` - reads attr.type (but see “[Determining whether a key slot is occupied](#determining-whether-a-key-slot-is-occupied)”)
* `psa_key_slot_get_flags` - reads attr.flags

`psa_crypto_slot_management.c`:
* `psa_get_and_lock_key_slot_in_memory` - reads attr.id
* `psa_get_empty_key_slot` - reads attr.lifetime
* `psa_load_persistent_key_into_slot` - passes attr pointer to psa_load_persistent_key
* `psa_load_persistent_key` - reads attr.id and passes pointer to psa_parse_key_data_from_storage
* `psa_parse_key_data_from_storage` - writes to many attributes
* `psa_get_and_lock_key_slot` - writes to attr.id, attr.lifetime, and attr.policy.usage
* `psa_purge_key` - reads attr.lifetime, calls psa_wipe_key_slot
* `mbedtls_psa_get_stats` - reads attr.lifetime, attr.id

`psa_crypto.c`:
* `psa_get_and_lock_key_slot_with_policy` - reads attr.type, attr.policy.
* `psa_get_and_lock_transparent_key_slot_with_policy` - reads attr.lifetime
* `psa_destroy_key` - reads attr.lifetime, attr.id
* `psa_get_key_attributes` - copies all publicly available attributes of a key
* `psa_export_key` - copies attributes
* `psa_export_public_key` - reads attr.type, copies attributes
* `psa_start_key_creation` - writes to the whole attr structure 
* `psa_validate_optional_attributes` - reads attr.type, attr.bits
* `psa_import_key` - reads attr.bits
* `psa_copy_key` - reads attr.bits, attr.type, attr.lifetime, attr.policy
* `psa_mac_setup` - copies whole attr structure
* `psa_mac_compute_internal` - copies whole attr structure
* `psa_verify_internal` - copies whole attr structure
* `psa_sign_internal` - copies whole attr structure, reads attr.type
* `psa_assymmetric_encrypt` - reads attr.type
* `psa_assymetric_decrypt` - reads attr.type
* `psa_cipher_setup` - copies whole attr structure, reads attr.type
* `psa_cipher_encrypt` - copies whole attr structure, reads attr.type
* `psa_cipher_decrypt` - copies whole attr structure, reads attr.type
* `psa_aead_encrypt` - copies whole attr structure
* `psa_aead_decrypt` - copies whole attr structure
* `psa_aead_setup` - copies whole attr structure
* `psa_generate_derived_key_internal` - reads attr.type, writes to and reads from attr.bits, copies whole attr structure
* `psa_key_derivation_input_key` - reads attr.type
* `psa_key_agreement_raw_internal` - reads attr.type and attr.bits

#### Determining whether a key slot is occupied

`psa_is_key_slot_occupied` currently uses the `attr.type` field to determine whether a key slot is occupied. This works because we maintain the invariant that an occupied slot contains key material. With concurrency, it is desirable to allow a key slot to be reserved, but not yet contain key material or even metadata. When creating a key, determining the key type can be costly, for example when loading a persistent key from storage or (not yet implemented) when importing or unwrapping a key using an interface that determines the key type from the data that it parses. So we should not need to hold the global key store lock while the key type is undetermined.

Instead, `psa_is_key_slot_occupied` should use the key identifier to decide whether a slot is occupied. The key identifier is always readily available: when allocating a slot for a persistent key, it's an input of the function that allocates the key slot; when allocating a slot for a volatile key, the identifier is calculated from the choice of slot.

#### Key slot content

Other than what is used to determine the [“key slot state”](#key-slot-state), the contents of a key slot are only accessed as follows:

* Modification during key creation (between `psa_start_key_creation` and `psa_finish_key_creation` or `psa_fail_key_creation`).
* Destruction in `psa_wipe_key_slot`.
* Read in many functions, between calls to `psa_lock_key_slot` and `psa_unlock_key_slot`.

**slot->key access:** 
* `psa_allocate_buffer_to_slot` - allocates key.data, sets key.bytes;
* `psa_copy_key_material_into_slot` - writes to key.data
* `psa_remove_key_data_from_memory` - writes and reads to/from key data
* `psa_get_key_attributes` - reads from key data
* `psa_export_key` - passes key data to psa_driver_wrapper_export_key
* `psa_export_public_key` - passes key data to psa_driver_wrapper_export_public_key
* `psa_finish_key_creation` - passes key data to psa_save_persistent_key
* `psa_validate_optional_attributes` - passes key data and bytes to mbedtls_psa_rsa_load_representation
* `psa_import_key` - passes key data to psa_driver_wrapper_import_key
* `psa_copy_key` - passes key data to psa_driver_wrapper_copy_key, psa_copy_key_material_into_slot
* `psa_mac_setup` - passes key data to psa_driver_wrapper_mac_sign_setup, psa_driver_wrapper_mac_verify_setup
* `psa_mac_compute_internal` - passes key data to psa_driver_wrapper_mac_compute
* `psa_sign_internal` - passes key data to psa_driver_wrapper_sign_message, psa_driver_wrapper_sign_hash
* `psa_verify_internal` - passes key data to psa_driver_wrapper_verify_message, psa_driver_wrapper_verify_hash
* `psa_asymmetric_encrypt` - passes key data to mbedtls_psa_rsa_load_representation
* `psa_asymmetric_decrypt` - passes key data to mbedtls_psa_rsa_load_representation
* `psa_cipher_setup ` - passes key data to psa_driver_wrapper_cipher_encrypt_setup and psa_driver_wrapper_cipher_decrypt_setup
* `psa_cipher_encrypt` - passes key data to psa_driver_wrapper_cipher_encrypt
* `psa_cipher_decrypt` - passes key data to psa_driver_wrapper_cipher_decrypt
* `psa_aead_encrypt` - passes key data to psa_driver_wrapper_aead_encrypt
* `psa_aead_decrypt` - passes key data to psa_driver_wrapper_aead_decrypt
* `psa_aead_setup` - passes key data to psa_driver_wrapper_aead_encrypt_setup and psa_driver_wrapper_aead_decrypt_setup
* `psa_generate_derived_key_internal` - passes key data to psa_driver_wrapper_import_key
* `psa_key_derivation_input_key` - passes key data to psa_key_derivation_input_internal
* `psa_key_agreement_raw_internal` - passes key data to mbedtls_psa_ecp_load_representation
* `psa_generate_key` - passes key data to psa_driver_wrapper_generate_key

### Random generator

The PSA RNG can be accessed both from various PSA functions, and from application code via `mbedtls_psa_get_random`.

With the built-in RNG implementations using `mbedtls_ctr_drbg_context` or `mbedtls_hmac_drbg_context`, querying the RNG with `mbedtls_xxx_drbg_random()` is thread-safe (protected by a mutex inside the RNG implementation), but other operations (init, free, seed) are not.

When `MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG` is enabled, thread safety depends on the implementation.

### Driver resources

Depends on the driver. The PSA driver interface specification does not discuss whether drivers must support concurrent calls.

## Simple global lock strategy

Have a single mutex protecting all accesses to the key store and other global variables. In practice, this means every PSA API function needs to take the lock on entry and release on exit, except for:

* Hash function.
* Accessors for key attributes and other local structures.

Note that operation functions do need to take the lock, since they need to prevent the destruction of the key.

Note that this does not protect access to the RNG via `mbedtls_psa_get_random`, which is guaranteed to be thread-safe when `MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG` is disabled.

This approach is conceptually simple, but requires extra instrumentation to every function and has bad performance in a multithreaded environment since a slow operation in one thread blocks unrelated operations on other threads.

## Global lock excluding slot content

Have a single mutex protecting all accesses to the key store and other global variables, except that it's ok to access the content of a key slot without taking the lock if one of the following conditions holds:

* The key slot is in a state that guarantees that the thread has exclusive access.
* The key slot is in a state that guarantees that no other thread can modify the slot content, and the accessing thread is only reading the slot.

Note that a thread must hold the global mutex when it reads or changes a slot's state.

### Slot states

For concurrency purposes, a slot can be in one of three states:

* UNUSED: no thread is currently accessing the slot. It may be occupied by a volatile key or a cached key.
* WRITING: a thread has exclusive access to the slot. This can only happen in specific circumstances as detailed below.
* READING: any thread may read from the slot.

A high-level view of state transitions:

* `psa_get_empty_key_slot`: UNUSED → WRITING.
* `psa_get_and_lock_key_slot_in_memory`: UNUSED or READING → READING. This function only accepts slots in the UNUSED or READING state. A slot with the correct id but in the WRITING state is considered free.
* `psa_unlock_key_slot`: READING → UNUSED or READING.
* `psa_finish_key_creation`: WRITING → READING.
* `psa_fail_key_creation`: WRITING → UNUSED.
* `psa_wipe_key_slot`: any → UNUSED. If the slot is READING or WRITING on entry, this function must wait until the writer or all readers have finished. (By the way, the WRITING state is possible if `mbedtls_psa_crypto_free` is called while a key creation is in progress.) See [“Destruction of a key in use”](#destruction of a key in use).

The current `state->lock_count` corresponds to the difference between UNUSED and READING: a slot is in use iff its lock count is nonzero, so `lock_count == 0` corresponds to UNUSED and `lock_count != 0` corresponds to READING.

There is currently no indication of when a slot is in the WRITING state. This only happens between a call to `psa_start_key_creation` and a call to one of `psa_finish_key_creation` or `psa_fail_key_creation`. This new state can be conveyed by a new boolean flag, or by setting `lock_count` to `~0`.

### Destruction of a key in use

Problem: a key slot is destroyed (by `psa_wipe_key_slot`) while it's in use (READING or WRITING).

TODO: how do we ensure that? This needs something more sophisticated than mutexes (concurrency number >2)! Even a per-slot mutex isn't enough (we'd need a reader-writer lock).

Solution: after some team discussion, we've decided to rely on a new threading abstraction which mimics C11 (i.e. `mbedtls_fff` where `fff` is the C11 function name, having the same parameters and return type, with default implementations for C11, pthreads and Windows). We'll likely use condition variables in addition to mutexes.
