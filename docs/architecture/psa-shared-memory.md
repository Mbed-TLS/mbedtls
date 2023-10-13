PSA API functions and shared memory
===================================

## Introduction

This document discusses the security architecture of systems where PSA API functions might receive arguments that are in memory that is shared with an untrusted process. On such systems, the untrusted process might access a shared memory buffer while the cryptography library is using it, and thus cause unexpected behavior in the cryptography code.

### Core assumptions

We assume the following scope limitations:

* Only PSA Crypto API functions are in scope (including Mbed TLS extensions to the official API specification). Legacy crypto, X.509, TLS, or any other function which is not called `psa_xxx` is out of scope.
* We only consider [input buffers](https://arm-software.github.io/psa-api/crypto/1.1/overview/conventions.html#input-buffer-sizes) and [output buffers](https://arm-software.github.io/psa-api/crypto/1.1/overview/conventions.html#output-buffer-sizes). Any other data is assumed to be in non-shared memory.

## System architecture discussion

### Architecture overview

We consider a system that has memory separation between partitions: a partition can't access another partition's memory directly. Partitions are meant to be isolated from each other: a partition may only affect the integrity of another partition via well-defined system interfaces. For example, this can be a Unix/POSIX-like system that isolates processes, or isolation between the secure world and the non-secure world relying on a mechanism such as TrustZone, or isolation between secure-world applications on such a system.

More precisely, we consider such a system where our PSA Crypto implementation is running inside one partition, called the **crypto service**. The crypto service receives remote procedure calls (RPC) from other partitions, validates their arguments (e.g. validation of key identifier ownership), and calls a PSA Crypto API function. This document is concerned with environments where the arguments passed to a PSA Crypto API function may be in shared memory (as opposed to environments where the inputs are always copied into memory that is solely accessible by the crypto service before calling the API function, and likewise with output buffers after the function returns).

When the data is accessible to another partition, there is a risk that this other partition will access it while the crypto implementation is working. Although this could be prevented by suspending the whole system while crypto is working, such a limitation is rarely desirable and most systems don't offer a way to do it. (Even systems that have absolute thread priorities, and where crypto has a higher priority than any untrusted partition, may be vulnerable due to having multiple cores or asynchronous data transfers with peripherals.)

The crypto service must guarantee that it behaves as if the rest of the world was suspended while it is executed. A behavior that is only possible if an untrusted entity accesses a buffer while the crypto service is processing the data is a security violation.

### Risks and vulnerabilities

We consider a security architecture with two or three entities:

* a crypto service, which offers PSA crypto API calls over RPC (remote procedure call) using shared memory for some input or output arguments;
* a client of the crypto service, which makes a RPC to the crypto service;
* in some scenarios, a client of the client, which makes a RPC to the crypto client which re-shares the memory with the crypto service.

The behavior of RPC is defined for in terms of values of inputs and outputs. This models an ideal world where the content of input and output buffers is not accessible outside the crypto service while it is processing an RPC. It is a security violation if the crypto service behaves in a way that cannot be achieved by setting the inputs before the RPC call, and reading the outputs after the RPC call is finished.

#### Read-read inconsistency

If an input argument is in shared memory, there is a risk of a **read-read inconsistency**:

1. The crypto code reads part of the input and validates it, or injects it into a calculation.
2. The client (or client's client) modifies the input.
3. The crypto code reads the same part again, and performs an action which would be impossible if the input had had the same value all along.

Vulnerability example (parsing): suppose the input contains data with a type-length-value or length-value encoding (for example, importing an RSA key). The crypto code reads the length field and checks that it fits within the buffer. (This could be the length of the overall data, or the length of an embedded field) Later, the crypto code reads the length again and uses it without validation. A malicious client can modify the length field in the shared memory between the two reads and thus cause a buffer overread on the second read.

Vulnerability example (dual processing): consider an RPC to perform authenticated encryption, using a mechanism with an encrypt-and-MAC structure. The authenticated encryption implementation separately calculates the ciphertext and the MAC from the plantext. A client sets the plaintext input to `"PPPP"`, then starts the RPC call, then changes the input buffer to `"QQQQ"` while the crypto service is working.

* Any of `enc("PPPP")+mac("PPPP")`, `enc("PPQQ")+mac("PPQQ")` or `enc("QQQQ")+mac("QQQQ")` are valid outputs: they are outputs that can be produced by this authenticated encryption RPC.
* If the authenticated encryption calculates the ciphertext before the client changes the output buffer and calculates the MAC after that change, reading the input buffer again each time, the output will be `enc("PPPP")+mac("QQQQ")`. There is no input that can lead to this output, hence this behavior violates the security guarantees of the crypto service.

#### Write-read inconsistency

If an output argument is in shared memory, there is a risk of a **write-read inconsistency**:

1. The crypto code writes some intermediate data into the output buffer.
2. The client (or client's client) modifies the intermediate data.
3. The crypto code reads the intermediate data back and continues the calculation, leading to an outcome that would not be possible if the intermediate data had not been modified.

Vulnerability example: suppose that an RSA signature function works by formatting the data in place in the output buffer, then applying the RSA private-key operation in place. (This is how `mbedtls_rsa_pkcs1_sign` works.) A malicious client may write badly formatted data into the buffer, so that the private-key operation is not a valid signature (e.g. it could be a decryption), violating the RSA key's usage policy.

Vulnerability example with chained calls: we consider the same RSA signature operation as before. In this example, we additionally assume that the data to sign comes from an attestation application which signs some data on behalf of a final client: the key and the data to sign are under the attestation application's control, and the final client must not be able to obtain arbitrary signatures. The final client shares an output buffer for the signature with the attestation application, and the attestation application re-shares this buffer with the crypto service. A malicious final client can modify the intermediate data and thus sign arbitrary data.

#### Write-write disclosure

If an output argument is in shared memory, there is a risk of a **write-write disclosure**:

1. The crypto code writes some intermediate data into the output buffer. This intermediate data must remain confidential.
2. The client (or client's client) reads the intermediate data.
3. The crypto code overwrites the intermediate data.

Vulnerability example with chained calls (temporary exposure): an application encrypts some data, and lets its clients store the ciphertext. Clients may not have access to the plaintext. To save memory, when it calls the crypto service, it passes an output buffer that is in the final client's memory. Suppose the encryption mechanism works by copying its input to the output buffer then encrypting in place (for example, to simplify considerations related to overlap, or because the implementation relies on a low-level API that works in place). In this scenario, the plaintext is exposed to the final client while the encryption in progress, which violates the confidentiality of the plaintext.

Vulnerability example with chained calls (backtrack): we consider a provisioning application that provides a data encryption service on behalf of multiple clients, using a single shared key. Clients are not allowed to access each other's data. The provisioning application isolates clients by including the client identity in the associated data. Suppose that an AEAD decryption function processes the ciphertext incrementally by simultaneously writing the plaintext to the output buffer and calculating the tag. (This is how AEAD decryption usually works.) At the end, if the tag is wrong, the decryption function wipes the output buffer. Assume that the output buffer for the plaintext is shared from the client to the provisioning application, which re-shares it with the crypto service. A malicious client can read another client (the victim)'s encrypted data by passing the ciphertext to the provisioning application, which will attempt to decrypt it with associated data identifying the requesting client. Although the operation will fail beacuse the tag is wrong, the malicious client still reads the victim plaintext.

#### Write-read feedback

If a function both has an input argument and an output argument in shared memory, and processes its input incrementally to emit output incrementally, the following sequence of events is possible:

1. The crypto code processes part of the input and writes the corresponding part of the output.
2. The client reads the early output and uses that to calculate the next part of the input.
3. The crypto code processes the rest of the input.

There are cryptographic mechanisms for which this breaks security properties. An example is [CBC encryption](https://link.springer.com/content/pdf/10.1007/3-540-45708-9_2.pdf): if the client can choose the content of a plaintext block after seeing the immediately preceding ciphertext block, this gives the client a decryption oracle. This is a security violation if the key policy only allowed the client to encrypt, not to decrypt.

TODO: is this a risk we want to take into account? Although this extends the possible behaviors of the one-shot interface, the client can do the same thing legitimately with the multipart interface.

### Possible countermeasures

In this section, we briefly discuss generic countermeasures.

#### Copying

Copying is a valid countermeasure. It is conceptually simple. However, it is often unattractive because it requires additional memory and time.

Note that although copying is very easy to write into a program, there is a risk that a compiler (especially with whole-program optimization) may optimize the copy away, if it does not understand that copies between shared memory and non-shared memory are semantically meaningful.

Example: the PSA Firmware Framework 1.0 forbids shared memory between partitions. This restriction is lifted in version 1.1 due to concerns over RAM usage.

#### Careful accesses

The following rules guarantee that shared memory cannot result in a security violation other than [write-read feedback](#write-read feedback):

* Never read the same input twice at the same index.
* Never read back from an output.
* Never write to the output twice at the same index.
    * This rule can usefully be relaxed in many circumstances. It is ok to write data that is independent of the inputs (and not otherwise confidential), then overwrite it. For example, it is ok to zero the output buffer before starting to process the input.

These rules are very difficult to enforce.

Example: these are the rules that a GlobalPlatform TEE Trusted Application (application running on the secure side of TrustZone on Cortex-A) must follow.

## Protection requirements

### Responsibility for protection

A call to a crypto service to perform a crypto operation involves the following components:

1. The remote procedure call framework provided by the operating system.
2. The code of the crypto service.
3. The code of the PSA Crypto dispatch layer (also known as the core), which is provided by Mbed TLS.
4. The implementation of the cryptographic mechanism, which may be provided by Mbed TLS or by a third-party driver.

The [PSA Crypto API specification](https://arm-software.github.io/psa-api/crypto/1.1/overview/conventions.html#stability-of-parameters) puts the responsibility for protection on the implementation of the PSA Crypto API, i.e. (3) or (4).

> In an environment with multiple threads or with shared memory, the implementation carefully accesses non-overlapping buffer parameters in order to prevent any security risk resulting from the content of the buffer being modified or observed during the execution of the function. (...)

In Mbed TLS 2.x and 3.x up to and including 3.5.0, there is no defense against buffers in shared memory. The responsibility shifts to (1) or (2), but this is not documented.

In the remainder of this chapter, we will discuss how to implement this high-level requirement where it belongs: inside the implementation of the PSA Crypto API. Note that this allows two possible levels: in the dispatch layer (independently of the implementation of each mechanism) or in the driver (specific to each implementation).

#### Protection in the dispatch layer

The dispatch layer has no control over how the driver layer will access buffers. Therefore the only possible protection at this layer method is to ensure that drivers have no access to shared memory. This means that any buffer located in shared memory must be copied into or out of a buffer in memory owned by the crypto service (heap or stack). This adds inefficiency, mostly in terms of RAM usage.

For buffers with a small static size limit, this is something we often do for convenience, especially with output buffers. However, as of Mbed TLS 3.5.0, it is not done systematically.

It is ok to skip the copy if it is known for sure that a buffer is not in shared memory. However, the location of the buffer is not under the control of Mbed TLS. This means skipping the copy would have to be a compile-time or run-time option which has to be set by the application using Mbed TLS. This is both an additional maintenance cost (more code to analyze, more testing burden), and a residual security risk in case the party who is responsible for setting this option does not set it correctly. As a consequence, Mbed TLS will not offer this configurability unless there is a compelling argument.

#### Protection in the driver layer

Putting the responsibility for protection in the driver layer increases the overall amount of work since there are more driver implementations than dispatch implementations. (This is true even inside Mbed TLS: almost all API functions have multiple underlying implementations, one for each algorithm.) It also increases the risk to the ecosystem since some drivers might not protect correctly. Therefore having drivers be responsible for protection is only a good choice if there is a definite benefit to it, compared to allocating an internal buffer and copying. An expected benefit in some cases is that there are practical protection methods other than copying.

Some cryptographic mechanisms are naturally implemented by processing the input in a single pass, with a low risk of ever reading the same byte twice, and by writing the final output directly into the output buffer. For such mechanism, it is sensible to mandate that drivers respect these rules.

In the next section, we will analyze how susceptible various cryptographic mechanisms are to shared memory vulnerabilities.

### Susceptibility of different mechanisms

#### Operations involving small buffers

For operations involving **small buffers**, the cost of copying is low. For many of those, the risk of not copying is high:

* Any parsing of formatted data has a high risk of [read-read inconsistency](#read-read-inconsistency).
* An internal review shows that for RSA operations, it is natural for an implementation to have a [write-read inconsistency](#write-read-inconsistency) or a [write-write disclosure](#write-write-disclosure).

Note that in this context, a “small buffer” is one with a size limit that is known at compile time, and small enough that copying the data is not prohibitive. For example, an RSA key fits in a small buffer. A hash input is not a small buffer, even if it happens to be only a few bytes long in one particular call.

The following buffers are considered small buffers:

* Any input or output from asymmetric cryptography (signature, encryption/decryption, key exchange, PAKE), including key import and export.
* The output of a hash or MAC operation.
* Cooked key derivation output.

**Design decision: the dispatch layer shall copy all small buffers**.

#### Symmetric cryptography inputs

Message inputs to hash, MAC, cipher (plaintext or ciphertext), AEAD (associated data, plaintext, ciphertext) and key derivation operations are at a low risk of [read-read inconsistency](#read-read-inconsistency) because they are unformatted data, and for all specified algorithms, it is natural to process the input one byte at a time.

**Design decision: require symmetric cryptography drivers to read their input without a risk of read-read inconsistency**.

TODO: what about IV/nonce inputs? They are typically small, but don't necessarily have a static size limit (e.g. GCM recommends a 12-byte nonce, but also allows large nonces).

#### Key derivation outputs

Key derivation typically emits its output as a stream, with no error condition detected after setup other than operational failures (e.g. communication failure with an accelerator) or running out of data to emit (which can easily be checked before emitting any data, since the data size is known in advance).

(Note that this is about raw byte output, not about cooked key derivation, i.e. deriving a structured key, which is considered a [small buffer](#operations-involving-small-buffers).)

**Design decision: require key derivation drivers to emit their output without reading back from the output buffer**.

#### Cipher and AEAD outputs

AEAD decryption is at risk of [write-write disclosure](#write-write-disclosure) when the tag does not match.

Cipher and AEAD outputs are at risk of [write-read-inconsistency](#write-read-inconsistency) and [write-write disclosure](#write-write-disclosure) if they are implemented by copying the input into the output buffer with `memmove`, then processing the data in place. In particular, this approach makes it easy to fully support overlapping, since `memmove` will take care of overlapping cases correctly, which is otherwise hard to do portably (C99 does not offer an efficient, portable way to check whether two buffers overlap).

**Design decision: the dispatch layer shall allocate an intermediate buffer for cipher and AEAD outputs**.

## Design of shared memory protection

This section explains how Mbed TLS implements the shared memory protection strategy summarized below.

### Shared memory protection strategy

* The core (dispatch layer) shall make a copy of the following buffers, so that drivers do not receive arguments that are in shared memory:
    * Any input or output from asymmetric cryptography (signature, encryption/decryption, key exchange, PAKE), including key import and export.
    * The output of a hash or MAC operation.
    * Cooked key derivation output.

* A document shall explain the requirements on drivers for arguments whose access needs to be protected:
    * Hash and MAC input.
    * Cipher/AEAD IV/nonce (to be confirmed).
    * Key derivation input (excluding key agreement).
    * Raw key derivation output (excluding cooked key derivation output).

* The built-in implementations of cryptographic mechanisms with arguments whose access needs to be protected shall protect those arguments.

Justification: see “[Susceptibility of different mechanisms](susceptibility-of-different-mechanisms)”.

### Implementation of copying

Copy what needs copying. This seems straightforward.

### Validation of copying

TODO

Proposed general idea: have tests where the test code calling API functions allocates memory in a certain pool, and code in the library allocates memory in a different pool. Test drivers check that needs-copying arguments are within the library pool, not within the test pool.

### Shared memory protection requirements

TODO: write document and reference it here.

### Validation of protection for built-in mechanisms

TODO

## Analysis of argument protection in built-in mechanisms

TODO
