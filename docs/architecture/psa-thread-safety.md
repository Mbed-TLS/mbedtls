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

## Resources left to protect

Analysis of the behavior of the PSA key store as of Mbed TLS 9202ba37b19d3ea25c8451fd8597fce69eaa6867, reduced by items protected by PR https://github.com/Mbed-TLS/mbedtls/pull/5673.

### Global variables
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

### Random generator

The PSA RNG can be accessed both from various PSA functions, and from application code via `mbedtls_psa_get_random`.

With the built-in RNG implementations using `mbedtls_ctr_drbg_context` or `mbedtls_hmac_drbg_context`, querying the RNG with `mbedtls_xxx_drbg_random()` is thread-safe (protected by a mutex inside the RNG implementation), but other operations (init, free, seed) are not.

When `MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG` is enabled, thread safety depends on the implementation.

### Driver resources

Depends on the driver. The PSA driver interface specification does not discuss whether drivers must support concurrent calls.

## Proposed strategy

### Slot states

Each key slot can be in one of the following states:
```
    PSA_STATE_EMPTY,     /* No key loaded yet. */
    PSA_STATE_CREATING,  /* Key creation has been started. */
    PSA_STATE_UNUSED,    /* Key present, but unused. */
    PSA_STATE_READING,   /* Key material used in an operation. */
    PSA_STATE_WIPING,    /* Purging key data from memory in progress. */
    PSA_STATE_DESTROYING /* Persistent and volatile key material destruction in progress. */
```
#### A high-level view of state transitions
```
           ┌──────────┐  ┌──────────┐
      ┌────┤  EMPTY   ◄──┤DESTROYING│
      │    └─┬────┬──▲┘  └──▲──▲────┘
┌─────▼────┐ │ ┌──▼──┴────┐ │  │
│ CREATING │ │ │  WIPING  ├─┘  │
└──┬─┬─────┘ │ └──────▲───┘    │
   │ │  ┌────▼─────┐  ├────────┘
   │ └──►  UNUSED  ├──┤
   │    └──▲────┬──┘  │
   │  ┌─┬──┴────▼──┐  │
   │  └─► READING  ├──┤
   │    └──────────┘  │
   └──────────────────┘
``` 

#### Details on state transitions

**State transitions from:**  
**Empty state:**  
-> Wiping: cleaning slots in  `psa_wipe_all_key_slots`:  `psa_crypto_init`.  
-> Unused: importing an existing key that does not require creation:  `psa_load_persistent_key_into_slot`,  `psa_load_builtin_key_into_slot`.  
-> Creating:  `psa_import_key`,  `psa_copy_key`,  `psa_key_derivation_output_key`,  `psa_generate_key`.

**Creating state:**  
-> Wiping:  `psa_fail_key_creation`.  
-> Destroying: UNUSED; TODO - could/should it happen?  
-> Unused:  `psa_finish_key_creation`  from  `psa_import_key`,  `psa_copy_key`,  `psa_key_derivation_output_key`,  `psa_generate_key`.

**Unused state:**  
-> Reading: Any operation that needs to read the key material. Copying, exporting, signing, verifying, enc/dec... via  `psa_get_and_lock_key_slot_with_policy`.  
-> Wiping:  `psa_purge_key`,  `psa_close_key`, but also  `psa_get_empty_key_slot`  if there's an unused persistent key.  
-> Destroying:  `psa_destroy_key`.

**Reading state:**  
-> Reading: another reader added via  `psa_get_and_lock_key_slot_with_policy`.  
-> Unused:  `psa_unlock_key_slot`  by the last reader.  
-> Wiping:  `psa_purge_key`,  `psa_close_key`;  
-> Destroying:  `psa_destroy_key`.

**Wiping state:**  
-> Destroying:  `psa_destroy_key`.  
-> Empty:  `psa_wipe_key`  from  `psa_close_key`,  `psa_purge_key`, but also delayed wiping when the last reader is unlocked in  `psa_unlock_key_slot`. Failures in  `psa_get_and_lock_key_slot`,  `psa_get_empty_key_slot`.

**Destroying state:**  
-> Empty:  `psa_finish_key_destruction`  (also calls  `psa_wipe_key`),  `psa_destroy_key`  if there are no readers, and if there was - unlocking the last one via  `psa_unlock_key_slot`.

#### Implementation details
The key slot data and metadata are protected by a single, global mutex. Each change of data/metadata and each read of a slot state requires locking it. Please note, however, that reading the key data itself does not have to be guarded by a mutex, given that `psa_get_and_lock_key_slot` is called prior to it. This function will lock the mutex, transition the key slot to the `PSA_STATE_READING` state, increase the reader counter, and release the mutex. This guarantees that the key slot data/metadata (apart from the reader counter) will not be modified until the last reader unlocks the slot by calling `psa_unlock_key_slot`.

#### Intent reasoning
To be able to atomically get a key slot and move it to a desired state (or add a reader), a new concept called `intent` was added to `psa_get_and_lock_key_slot` calls. Possible intents: 
 - `Read` - used widely for all operations that read key slot data, moves the key to `PSA_STATE_READING` and adds a reader;
 - `Destroy` - get key slot and move it to `PSA_STATE_DESTROYING` state;
 - `Open` - to provide functionality for the to-be-deprecated `psa_open_key`, which gets the key handle but does not change its state.

#### Destroying / wiping a key in use
If there is a request for key destruction / wiping while the key is in use (`PSA_STATE_READING`), the state will change to `PSA_STATE_DESTROYING` or `PSA_STATE_WIPING`, but the call will return `PSA_ERROR_DELAYED`. The operation itself will be performed once the last of readers unlocks the slot. 

#### Transitioning to the same state twice
Apart from the possible transition from `PSA_STATE_READING` to itself (when adding a new reader), it is not possible to transition to the same state. The reason behind this is to prevent double calls to slot creation, destruction, or wiping. 
