# AFL++ fuzzing campaign for the Mbed TLS harnesses

Self-contained scripts, seed corpora, and dictionaries to run an AFL++ campaign
against the in-repo `programs/fuzz/` harnesses.

## Layout

```
campaign/
├── build_targets.sh     # build all 14 harnesses × 5 AFL++ variants -> bin/
├── run_campaign.sh      # launch a distributed campaign for one harness
├── campaign_ctl.sh      # status / stop / crashes
├── gen_tls_seeds.c      # records real handshakes -> fuzz_client seeds
├── build_tls_seeds.sh   # builds + runs the generator above
├── seeds/<harness>/     # valid starting corpus per harness (committed)
├── dict/{der,tls}.dict  # trimmed dictionaries (committed)
├── corpus-manifest.json # provenance of seeds + dictionaries
├── bin/                 # built binaries (gitignored, produced by build_targets.sh)
└── output/<harness>/    # campaign output (gitignored, produced by run_campaign.sh)
```

## Requirements

AFL++ (`afl-clang-fast`, `afl-fuzz`) with its persistent libFuzzer driver
(`libAFLDriver.a`), plus `tmux` or `screen`. The harnesses build in the default
config; the build enables `MBEDTLS_PLATFORM_TIME_ALT` so `dummy_init()` pins a
constant clock (per `programs/fuzz/README.md`), keeping cert-time-dependent paths
deterministic.

## Usage

```bash
cd programs/fuzz/campaign
./build_targets.sh                      # once: builds bin/*_{normal,cmplog,asan,laf,cfisan}
./build_targets.sh fuzz_client          # build just one harness (fast incremental rebuild)
sudo afl-system-config                  # optional: best performance
./run_campaign.sh fuzz_x509crt          # fuzz one harness on 8 cores
./campaign_ctl.sh fuzz_x509crt status   # afl-whatsup summary
./campaign_ctl.sh fuzz_x509crt crashes  # crash count + triage hint
./campaign_ctl.sh fuzz_x509crt stop     # stop all its instances
```

`build_targets.sh` bounds parallelism to `AFL_BUILD_JOBS` (default `nproc`) and
prints a heartbeat per variant, so a slow instrumented build is not mistaken for a
hang. On a low-RAM box, lower it (`AFL_BUILD_JOBS=4 ./build_targets.sh`) if the
memory-heavy `laf`/`cmplog` compiles thrash into swap, or build a subset with
`AFL_VARIANTS="normal cmplog asan" ./build_targets.sh` to skip the slow `laf` one.

Pass one or more harness names to build only those instead of all 14
(`./build_targets.sh fuzz_client`). The shared library is still compiled once as a
dependency, but the other harness targets are skipped, and a targeted build reuses
its per-variant build dir for a fast incremental rebuild (e.g. after a library
change). A full build (no harness argument) wipes the build dir first; `AFL_CLEAN=1`
forces a from-scratch build and `AFL_CLEAN=0` forces reuse. Combine with
`AFL_VARIANTS` to narrow both axes, e.g. rebuild only the ASan `fuzz_client`:
`AFL_VARIANTS=asan ./build_targets.sh fuzz_client`.

Binaries are installed into `bin/` by copy-then-rename rather than a plain `cp`.
`cp` writes into the existing inode, so overwriting a binary a live `afl-fuzz`
instance is executing corrupts its text pages and kills the campaign a few
minutes later; `rename(2)` swaps the directory entry instead and running
instances keep the inode they started on. Rebuilding during a campaign is
therefore safe - but those instances go on running the old code until
`./campaign_ctl.sh <harness> stop` and a fresh `./run_campaign.sh <harness>`.

`run_campaign.sh <harness>` spawns a fixed set of 8 instances: one `-M` main,
one CMPLOG instance (`-c bin/<h>_cmplog -l 2a`), one ASAN instance, and 5 MOpt
(`-L 0`) secondaries each on a different power schedule (`fast coe exploit rare
seek`). The dictionary is auto-selected per harness
family (`der.dict` for X.509/PKCS#7/key/verify, `tls.dict` for the SSL/DTLS
harnesses).
Output goes to `$AFL_OUT_DIR/<harness>` (default `output/` next to the seeds and
dictionaries in this campaign directory).

## Deterministic RNG

Determinism comes from `MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG`, which `crypto_config.h`
enables (together with `MBEDTLS_PLATFORM_TIME_ALT`) whenever
`FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` is defined. `afl-clang-fast`
predefines that macro, so the campaign binaries get it automatically;
`dummy_init()` then calls `mbedtls_test_enable_insecure_external_rng()`, which
routes every PSA draw to libc `rand()`. Real entropy would otherwise be mixed in
and every execution would draw fresh randomness.

That matters because a TLS client picks a random 32-byte `ClientHello.random` and
a random 32-byte `legacy_session_id`, and TLS 1.3 requires the server to echo the
session id back. With per-run randomness no recorded server response can ever
match, so `fuzz_client`/`fuzz_dtlsclient` could never get past ServerHello — the
whole TLS 1.3 post-ServerHello surface (`parse_key_share_ext`,
`parse_encrypted_extensions`, `process_server_finished`, NewSessionTicket) and
everything behind a completed handshake (`mbedtls_ssl_read`, application data,
renegotiation) stayed at zero coverage. Fixing the RNG also stops random values
from perturbing AFL++'s edge feedback, which helps stability.

Two consequences. Anything built with a plain compiler — `build_tls_seeds.sh`,
coverage builds — must define `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` itself,
or it gets a different RNG than the harness and no recorded flight will replay
(and the entropy module stays on with no sources, so the build fails outright).
And `rand()` is one process-global stream that nothing resets, so a program
emitting more than one seed has to rewind it (`srand(1)`) before each, otherwise
only the first seed matches what a freshly started harness produces.

This is a fuzzing-only configuration; never ship it.

Harnesses: `fuzz_client fuzz_server fuzz_dtlsclient fuzz_dtlsserver fuzz_x509crt
fuzz_x509crl fuzz_x509csr fuzz_pkcs7 fuzz_ssl_session fuzz_ssl_context
fuzz_dtls_record fuzz_x509_verify fuzz_privkey fuzz_pubkey`.

`fuzz_privkey` and `fuzz_pubkey` live in `tf-psa-crypto/programs/fuzz/`, so they
build into a different subdirectory; `harness_build_path()` handles that. They
cover private/public key parsing (`pkparse.c`), which no other harness reaches
with attacker-controlled bytes, and both do a parse-then-write round trip.

`fuzz_server` configures a session cache unconditionally rather than behind an
options bit, because all 8 bits of its single options byte (`Data[Size-1]`) are
already assigned and widening it to two bytes would shift every existing corpus
entry's payload and reinterpret its flags. The cache is initialised and freed per
iteration, not kept static: a cache surviving across persistent-mode iterations
would make coverage depend on execution order and cost stability. Measured at
97% stability with it enabled.

That reaches the cache lookup path but not the store path. Storing a session
requires a *completed* server handshake, and no corpus input completes one -
`mbedtls_ssl_handshake_wrapup` is at zero across all 8108 entries, because a
fuzzer cannot produce a client Finished that verifies. `mbedtls_ssl_cache_set`,
`ssl_cache_pick_writing_slot`, `mbedtls_ssl_ticket_write` and
`ssl_write_new_session_ticket` are all blocked behind that. The fix is the mirror
of the `fuzz_client` seeds: record the *client* side of a real handshake. That
needs `gen_tls_seeds.c` to draw the server's randomness first (the opposite of
what it does now), since at replay the server is the only party consuming the
DRBG.

## Seeds

- **Parser harnesses** (`x509crt/crl/csr`, `pkcs7`): hand-curated valid samples
  harvested from `framework/data_files` (plus the shipped x509crt clusterfuzz
  reproducer), hash-deduplicated.
- **`x509_verify`**: `[u16 leaf-len][leaf DER][CA DER]` pairs built from test certs.
- **TLS/DTLS/session/context harnesses**: produced by driving real
  in-memory handshakes and dumping the record streams, a serialized session
  (`mbedtls_ssl_session_save`), and a serialized DTLS context
  (`mbedtls_ssl_context_save`).
- **`fuzz_client`**: regenerate with `./build_tls_seeds.sh` (see
  `gen_tls_seeds.c`). It runs real TLS 1.3 and TLS 1.2 handshakes against an
  in-process server and records the server's side, one seed per harness
  `options` value, continuing past Finished into NewSessionTicket and
  application data.

  These paths cannot be reached by mutation at all: TLS 1.3 makes the server
  echo the client's random 32-byte `legacy_session_id`, and the client checks it
  in `ssl_tls13_check_server_hello_session_id_echo()`. 791M executions got 58
  inputs as far as that check and none past it. A recorded flight only replays
  because the RNG is deterministic, so the generator must be built the same way
  the campaign is — `build_tls_seeds.sh` handles that.

  Two ordering constraints, both learned the hard way:
  the generator drives the client's ClientHello **before** setting the server up,
  because they share one PSA DRBG and the server's setup draws from it
  (`mbedtls_ssl_ticket_setup` generates an AES-256 key), which would shift the
  client's session id away from the harness's; and the pinned clock must lie
  inside the test certificates' validity window or `options & 4`
  (VERIFY_REQUIRED) can never produce a successful handshake.

  TLS 1.3 seeds complete the handshake. TLS 1.2 seeds get through the server
  flight (ServerHello, Certificate, ServerKeyExchange, CertificateRequest) and
  the client's response, but not Finished: a TLS 1.2 client draws its ECDHE key
  *after* ServerHello, by which point the server has also drawn, so the replayed
  client derives a different premaster than the recorded Finished was computed
  over. Reaching Finished for TLS 1.2 would need the server to consume no
  randomness at all, which one shared PSA DRBG cannot offer.

  Measured against the full 7,866-entry corpus, the 13 seeds take
  `ssl_tls13_client.c` from 22% to 46% of regions (50% to 85% of functions),
  `ssl_tls13_generic.c` 26%→53%, `ssl_tls13_keys.c` 15%→41%, and first reach
  `mbedtls_ssl_read` / `ssl_parse_inner_plaintext`. A 60s afl-fuzz run finds
  3083 edges from them versus 2411 from the previous two seeds.
- **`dtls_record`**: framed DTLS record bodies, each tagged with a trailing
  cipher-selector byte; the harness builds a matching transform so
  `mbedtls_ssl_check_record` exercises `mbedtls_ssl_decrypt_buf` across the
  AEAD and CBC-HMAC paths.
- **`privkey`/`pubkey`**: RSA and EC keys in every accepted container — PKCS#1,
  SEC1, PKCS#8, SPKI, RFC 8410 (X25519/Ed25519), EC with explicit domain
  parameters, encrypted PKCS#8 (PBES2/PBKDF2 across AES-128/256 and 3DES, with
  a SHA-512 PRF variant), and legacy `Proc-Type: 4,ENCRYPTED` PEM.
  Two format rules matter here, both read off `pkparse.c`: **PEM seeds must end
  in a NUL byte** (`key[keylen-1] != '\0'` skips the PEM branch outright), and
  encrypted keys are encrypted with the same constant password the harness
  passes, since `pwdlen == 0` returns `PASSWORD_REQUIRED` before any PBES2
  parameter is parsed.
- **`x509crt`/`x509_verify`**: additionally certificates carrying
  `certificatePolicies` (with CPS and userNotice qualifiers) and iPAddress SANs
  (IPv4 and IPv6), which reach the policy-printing and IP-matching paths that
  DNS-only certificates never touch.

See `corpus-manifest.json` for exact per-harness counts and provenance.

Note: coverage-based `afl-cmin` cannot minimize these harnesses — `afl-showmap`
does not feed the aflpp shared-memory testcase to persistent
`LLVMFuzzerTestOneInput` targets, so every input yields the same trace and cmin
collapses to one file. The corpora are hash-deduplicated curated/valid inputs
instead.

## Dictionaries

`dict/der.dict` and `dict/tls.dict` merge `AFL_LLVM_DICT2FILE` compiler-emitted
comparison tokens (DER OIDs, magic values) with curated format tokens (DER/ASN.1
tags, PEM markers, TLS/DTLS record/version/extension/ciphersuite constants), then
trimmed and validated to load.
