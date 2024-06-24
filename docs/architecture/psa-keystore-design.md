PSA key store design
====================

## Introduction

This document describes the architecture of the key storage in memory in the Mbed TLS and TF-PSA-Crypto implementation of the PSA Cryptography API.

In the PSA Cryptography API, cryptographic operations access key materials via a key identifier (key ID for short). Applications must first create a key object, which allocates storage in memory for the key material and metadata. This storage is under the control of the library and may be located in a different memory space such as a trusted execution environment or a secure element.

The storage of persistent keys is out of scope of this document. See the [Mbed Crypto storage specification](mbed-crypto-storage-specification.md).

## Key slot management interface

### Key store and key slots

The **key store** consists of a collection of **key slots**. Each key slot contains the metadata for one key, as well as the key material or a reference to the key material.

A key slot has the type `psa_key_slot_t`. The key store is a global object which is private inside `psa_crypto_slot_management.c`.

### Key slot entry points

The following operations allocate a key slot by calling `psa_reserve_free_key_slot()`:

* **Creating** a key object, through means such as import, random generation, deterministic derivation, copy, or registration of an existing key that is stored in protected hardware (secure element, hardware unique key (HUK)).
* **Loading** a persistent key from storage, or loading a built-in key. This is done through `psa_get_and_lock_key_slot()`, which calls `psa_reserve_free_key_slot()` and loads the key if applicable.

The following operations free a key slot by calling `psa_wipe_key_slot()` and, if applicable, `psa_free_key_slot()`:

* **Destroying** a key.
* **Purging** a persistent key from memory, either explicitly at the application's request or to free memory.

Deinitializing the PSA Crypto subsystem with `mbedtls_psa_crypto_free()` destroys all volatile keys and purges all persistent keys.

A key slot can be accessed:

* while the key is being created or loaded;
* while the key is being destroyed or purged;
* while the key metadata or key material is being accessed.

### Key slot states

The state of a key slot is indicated by its `state` field of type `psa_key_slot_state_t`, which can be:

* `PSA_SLOT_EMPTY`: a slot that occupies memory but does not currently contain a key.
* `PSA_SLOT_FILLING`: a slot that is being filled to create or load a key.
* `PSA_SLOT_FULL`: a slot containing a key.
* `PSA_SLOT_PENDING_DELETION`: a slot whose key is being destroy or purged.

#### Concurrency

In a multithreaded environment, since Mbed TLS 3.6.0, each key slot is protected by a reader-writer lock. (In earlier versions, the key store was not thread-safe.) The lock is controlled by a single global mutex `mbedtls_threading_psa_globaldata_mutex`. The concurrency state of the slot is indicated by the state and the `registered_readers` field:

* `EMPTY` or `FULL` state, `registered_readers == 0`: the slot is not in use by any thread.
* `FULL` state, `registered_readers != 0`: the slot is being read.
* `FILLING` or `PENDING_DELETION` state: the slot is being written.

For more information, see [PSA thread safety](psa-thread-safety/psa-thread-safety.md).

Note that a slot must not be moved in memory while it is being read or written.

## Key slot management implementations

### Key store implementation variants

There are three variants of the key store implementation, responding to different needs.

* Hybrid key store ([static key slots](#static-key-store) with dynamic key data): the key store is a statically allocated array of slots, of size `MBEDTLS_PSA_KEY_SLOT_COUNT`. Key material is allocated on the heap. This is the historical implementation.
* Fully [static key store](#static-key-store) (since Mbed TLS 3.6.1): the key store is a statically allocated array of slots, of size `MBEDTLS_PSA_KEY_SLOT_COUNT`. Each key slot contains the key representation directly, and the key representation must be no more than `MBEDTLS_PSA_KEY_SLOT_BUFFER_SIZE` bytes. This is intended for very constrained devices that do not have a heap.
* [Dynamic key store](#dynamic-key-store) (since Mbed TLS 3.6.1): the key store is dynamically allocated as multiple slices on the heap, with a size that adjusts to the application's usage. Key material is allocated on the heap. This is intended for higher-end devices where applications are not expected to have a highly predicatable resource usage.

#### Slice abstraction

Some parts of the key slot management code use **key slices** as an abstraction. A key slice is an array of key slots. Key slices are identified by a number which is a small non-negative integer.

* With a [static key store](#static-key-store), there is a single, statically allocated slice, with the number 0.
* With a [dynamic key store](#dynamic-key-store), there is statically allocated array of pointers to key slices. The slices are allocated on the heap as needed.

#### Key identifiers and slot location

When creating a volatile key, the slice containing the slot and index of the slot in its slice determine the key identifier. When accessing a volatile key, the slice and the slot index in the slice are calculated from the key identifier. The encoding of the slot location in the volatile key identifier is different for a [static](#volatile-key-identifiers-in-the-static-key-store) or [dynamic](#volatile-key-identifiers-in-the-dynamic-key-store) key store.

### Static key store

The static key store is the historical implementation. The key store is a statically allocated array of slots, of size `MBEDTLS_PSA_KEY_SLOT_COUNT`. This value is an upper bound for the total number of volatile keys plus loaded keys.

Since Mbed TLS 3.6.1, there are two variants for the static key store: a hybrid variant (default), and a fully-static variant enabled by the configuration option `MBEDTLS_PSA_STATIC_KEY_SLOTS`. The two variants have the same key store management: the only difference is in how the memory for key data is managed. With fully static key slots, the key data is directly inside the slot, and limited to `MBEDTLS_PSA_KEY_SLOT_BUFFER_SIZE` bytes. With the hybrid key store, the slot contains a pointer to the key data, which is allocated on the heap.

#### Volatile key identifiers in the static key store

For easy lookup, a volatile key whose index is `id` is stored at the index `id - PSA_KEY_ID_VOLATILE_MIN`.

#### Key creation with a static key store

To create a key, `psa_reserve_free_key_slot()` searches the key slot array until it finds one that is empty. If there are none, the code looks for a persistent key that can be purged (see [“Persistent key cache”](#persistent-key-cache)), and purges it. If no slot is free and no slot contains a purgeable key, the key creation fails.

#### Freeing a key slot with a static key store

With a static key store, `psa_wipe_key_slot()` destroys or purges a key by freeing any associated resources, then setting the key slot to the empty state. The slot is then ready for reuse.

### Dynamic key store

The dynamic key store allows a large number of keys, at the expense of more complex memory management.

#### Dynamic key slot performance characteristics

Key managmeent and key access have O(1) performance in terms of the total number of keys, except that allocating or freeing a slot may trigger a call to `calloc()` or `free()` on an amount of memory that is proportional to the maximum number of volatile keys ever used by the application.

The memory overhead is at most linear in the number of volatile keys currently used by the application. More precisely, the total number of key slots that consume memory is, at most, slightly more than twice the total number of volatile keys.

#### Key slices in the dynamic key store

The key slot is organized in slices, which are dynamically arrays of key slot. The number of slices is determined at compile time. The key store contains a static array of pointers to slices.

Volatile keys and loaded keys (persistent or built-in) are stored in separate slices.
Key slices number 0 to `KEY_SLOT_VOLATILE_SLICE_COUNT - 1` contain only volatile keys.
One key slice contains only loaded keys: that key slice is thus the cache slice. See [“Persistent key cache”](persistent-key-cache) for how the cache is managed.

#### Volatile key identifiers in the dynamic key store

A volatile key identifier encodes the slice index and the slot index at separate bit positions. That is, `key_id = BASE | slice_index | slot_index` where the bits set in `BASE`, `slice_index` and `slot_index` do not overlap.

#### From key slot to key slice

Some parts of the slot management code need to determine which key slice contain a key slot when given a pointer to the key slot. In principle, the key slice is uniquely determined from the key identifier which is located in the slot:

* for a volatile key identifier, the [slice index is encoded in the key identifier](#volatile-key-identifiers-in-the-dynamic-key-store);
* for a persistent key identifier or built-in key identifier, [the slot is in the sole cache slice](#key-slices-in-the-dynamic-key-store).

Nonetheless, we store the slice index as a field in the slot, for two reasons:

* It is more robust in case the slice assignment becomes more complex in the future or is somehow buggy.
* It allows the slot to slice correspondence to work even if the key identifier field has not been filled yet or has been wiped. The implementation in Mbed TLS 3.6.1 requires this because `psa_wipe_key_slot()` wipes the slot, then calls `psa_free_key_slot()`, which needs to determine the slice. Keeping the slice index as a separate field allows us to better separate the concerns of key liveness and slot liveness. A redesign of the internal interfaces could improve this, but would be too disruptive in the 3.6 LTS branch.

#### Length of the volatile key slices

The volatile key slices have exponentially increasing length: each slice is twice as long as the previous one. Thus if the length of slice 0 is `B` and there are `N` slices, then there are `B * (2^N - 1)` slots.

As of Mbed TLS 3.6.1, the maximum number of volatile key slots is less than the theoretical maximum of 2^30 - 2^16 (0x10000000..0x7ffeffff, the largest range of key identifiers reserved for the PSA Crypto implementation that does not overlap the range for built-in keys). The reason is that we limit the slot index to 2^25-1 so that the [encoding of volatile key identifiers](#volatile-key-identifiers-in-the-dynamic-key-store) has 25 bits for the slot index.

When `MBEDTLS_TEST_HOOKS` is enabled, the length of key slices can be overridden. We use this in tests that need to fill the key store.

#### Free list

Each volatile key slice has a **free list**. This is a linked list of all the slots in the slice that are free. The global data contains a static array of free list heads, i.e. the index of a free slot in the slice. Each free slot contains the index of the next free slot in that slice's free list. The last element of the linked list (or the head if the list is empty) contains an index that is larger than the length of the slice,

As a small optimization, a free slot does not actually contain the index of the next slot, but the index of the next free slot on the list _relative to the next slot in the array_. This way, a slice freshly obtained from `calloc` has all of its slots in the free list in order. The absolute index of the next slot after slot `i` in the free list is `i + slice[i].next_free_relative_to_next`.

#### Dynamic key slot allocation

To create a volatile key, `psa_reserve_free_key_slot()` searches the free lists of each allocated slice until it finds a slice that is not full. If all allocated slices are full, the code allocates a new slice at the lowest possible slice index. If all possible slices are already allocated and full, the key creation fails.

The newly allocated slot is removed from the slice's free list.

We only allocate a slice of size `B * 2^k` if there are already `B * (2^k - 1)` occupied slots. Thus the memory overhead is at most `B` slots plus the number of occupied slots, i.e. the memory consumption for slots is at most than twice the required memory plus a small constant overhead.

#### Dynamic key slot deallocation

When destroying a volatile key, `psa_wipe_key_slot()` calls `psa_free_key_slot()`. This function adds the newly freed slot to the head of the free list.

##### Future improvement: slice deallocation

As of Mbed TLS 3.6.1, `psa_free_key_slot()` does not deallocate slices. Thus the memory consumption for slots never decreases (except when the PSA crypto subsystem is deinitialized). Freeing key slices intelligently would be a desirable improvement.

We should not free a key slice as soon as it becomes empty, because that would cause large allocations and deallocations if there are slices full of long-lived keys, and then one slice keeps being allocate and deallocated for the occasional short-lived keys. Rather, there should be some hysteresis, e.g. only deallocate a slice if there are at least T free slots in the previous slice.

Note that currently, the slice array contains one sequence of allocated slices followed by one sequence of unallocated slices. Mixing allocated and unallocated slices may make some parts of the code a little more complex, and should be tested thoroughly.

### Persistent key cache

Persistent keys and built-in keys need to be loaded into the in-memory key store each time they are accessed:

* while creating them;
* to access their metadata;
* to start performing an operation with the key;
* when destroying the key.

To avoid frequent storage access, we cache persistent keys in memory. This cache also applies to built-in keys.

With the [static key store](#static-key-store), a non-empty slot can contain either a volatile key or a cache entry for a persistent or built-in key. With the [dynamic key store](#dynamic-key-store), volatile keys and cached keys are placed in separate [slices](#key-slices-in-the-dynamic-key-store).

The persistent key cache is a fixed-size array of `MBEDTLS_PSA_KEY_SLOT_COUNT` slots. This array is shared with volatile keys in the static key store, and separate with the dynamic key store.

#### Accessing a persistent key

`psa_get_and_lock_key_slot()` automatically loads persistent and built-in keys if the specified key identifier is in the corresponding range. To that effect, it traverses the key cache to see if a key with the given identifier is already loaded. If not, it loads the key. This cache walk takes time that is proportional to the cache size.

#### Cache eviction

A key slot must be allocated in the cache slice:

* to create a volatile key (static key store only);
* to create a persistent key;
* to load a persistent or built-in key.

If the cache slice is full, the code will try to evict an entry. Only slots that do not have readers can be evicted (see [“Concurrency”](#concurrency)). In the static key store, slots containing volatile keys cannot be evicted.

As of Mbed TLS 3.6.1, there is no tracking of a key's usage frequency or age. The slot eviction code picks the first evictable slot it finds in its traversal order. We have not reasoned about or experimented with different strategies.
