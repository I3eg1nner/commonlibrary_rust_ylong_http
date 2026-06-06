# HTTPS-proxy benchmark — methodology & results

## What is measured

End-to-end HTTPS-proxy throughput/latency for the topology:

```
client --TLS--> HTTPS proxy --CONNECT tunnel--> origin HTTPS server (TLS-in-TLS)
```

Harness: `ylong_http_client/benches/https_proxy_bench.rs` (`harness = false`). It
starts an OpenSSL TLS-terminating CONNECT proxy and a TLS origin server (both
using the `tests/file` cert fixtures), then runs the identical workload through
`ylong_http_client` and through `libcurl` (the system `curl` binary).

## Fixed configuration

| Parameter | Value |
|-----------|-------|
| Measured requests | 2000 (sequential) |
| Warm-up requests (excluded) | 200 |
| Response payload | 1024 bytes |
| Connection reuse | keep-alive — one proxy tunnel reused for all requests (both clients) |
| TLS | OpenSSL defaults (`mozilla_intermediate` acceptor) on both hops |
| HTTP version | HTTP/1.1 on both clients (curl forced with `--http1.1`; origin is HTTP/1.1-only) |
| Verification | curl skips all verification (`--insecure`/`--proxy-insecure`); ylong additionally **verifies the proxy cert** against the root CA (a handicap against ylong, so the comparison is conservative) |

Primary metric: throughput (requests/second). Improvement = `(curl_time - ylong_time) / curl_time`.

## How to run

```
OPENSSL_DIR=<openssl-prefix> \
LD_LIBRARY_PATH=<openssl-prefix>/lib \
RUSTFLAGS="-L <openssl-prefix>/lib -l ssl -l crypto" \
cargo bench --no-default-features \
  --features async,http1_1,tokio_base,tls_default \
  --bench https_proxy_bench
```

## Important: two different baselines

The sub-task asks to compare against **libcurl (the library)**. There are two very
different things one can measure, and they give very different numbers:

1. **libcurl (library)** — link libcurl into the benchmark (via the `curl` crate's
   easy interface) and drive it in-process with a reused handle. This is the
   apples-to-apples *library-vs-library* comparison the target is about.
2. **`curl` CLI** — shell out to the `curl` command-line tool. Even when one curl
   process is reused for all requests, this still carries the CLI's per-URL
   transfer setup / argument handling overhead. It is **not** a library
   comparison and inflates ylong's apparent advantage.

The benchmark now measures **(1) as the primary result** and prints (2) for
reference only. TLS verification is configured identically for both ylong and
libcurl: proxy and origin certificates are verified against the test root CA,
hostname verification disabled.

## Results — RISC-V (SpacemiT K3), representative hardware

- **Hardware**: SpacemiT K3, RISC-V64 (`riscv64gc`), 8 cores, 7.7 GB RAM
- **OS**: Bianbu 4.0 (Ubuntu-based); **Toolchain**: rustc 1.96.0 stable, `bench` profile
- **OpenSSL**: system OpenSSL 3.5 — **the same library linked by both** ylong and libcurl 8.18
- Config: 2000 req, 200 warm-up, 1 KB payload, keep-alive (reused connection/tunnel), HTTP/1.1

Five consecutive runs (very low variance):

| Run | ylong req/s | **libcurl (library) req/s** | **Δ (vs library)** | curl CLI req/s (ref) |
|-----|-------------|------------------------------|---------------------|----------------------|
| 1 | 4,199 | 4,137 | +1.5% | 3,216 |
| 2 | 4,328 | 4,299 | +0.6% | 3,229 |
| 3 | 4,310 | 4,249 | +1.4% | 3,254 |
| 4 | 4,254 | 4,177 | +1.8% | 3,019 |
| 5 | 4,333 | 4,237 | +2.2% | 3,207 |
| **median** | **~4,310** | **~4,237** | **≈ +1.5%** (range +0.6%…+2.2%) | ~3,210 |

## Conclusion — honest assessment

- **Against libcurl (the library): `ylong_http_client` is essentially on par,
  ~1–2% faster (median ≈ +1.5%).** It does **NOT** reach the ≥20% target in the
  rigorous library-vs-library sense. Both clients are OpenSSL-bound on the same
  TLS-in-TLS path, so a large gap is not expected.
- The earlier **+26% (RISC-V) / +41.5% (x86)** figures were measured against the
  **`curl` CLI tool**, whose process/CLI overhead accounts for almost the entire
  difference (libcurl-the-library is ~30% faster than its own CLI here). Those
  numbers do **not** represent a real library performance advantage and are kept
  only as a CLI reference (ylong is ~+26% faster than the curl CLI on RISC-V).

**Net:** the HTTPS-proxy feature performs at parity with a mature C library
(libcurl) — a respectable result — but the "≥20% over libcurl" goal is **not met**
under a fair library-to-library comparison.

## Fine-grained analysis (ylong vs libcurl library, RISC-V)

Parameter sweep via `BENCH_KEEPALIVE` / `BENCH_PAYLOAD` / `BENCH_REQUESTS` (before optimization, clean nodelay fixture):

| Scenario | Δ (ylong vs libcurl lib) | Reading |
|----------|--------------------------|---------|
| keep-alive, payload 0 B | +2% | steady-state small request → ~parity / slight win |
| keep-alive, payload 1 KB | +1.5% | same |
| keep-alive, payload 256 KB | **−35%** | large body → ylong slower (data-path through nested TLS) |
| no keep-alive, 1 KB | slower | cold setup (full handshakes); also dominated by per-request client rebuild in the bench |

**Where ylong wins:** steady-state small messages on a reused connection — parity / +2%.
**Where ylong loses:** large bodies (−35%) and connection setup.

## Optimization attempts (task 6.4) — what worked and what didn't

Implemented and measured on the board:

- **6.4a TLS session resumption** (OpenSSL session cache, per-`SSL_CTX` keyed, gated off for pinned/custom-verifier configs for safety): correct + secure, but the bench can't demonstrate it (its no-keepalive mode rebuilds the client/`SSL_CTX` per request, so the per-ctx cache never hits). Helps real "one long-lived client, repeated cold connections to the same host" only.
- **6.4b read-drain loop**: **REVERTED** — measured a ~3% *regression* on large bodies, no benefit (`SSL_read` returns one record per call regardless).
- **Phase-1 larger read buffer (16KB→64KB) + `SSL_set_read_ahead` + `SSL_MODE_RELEASE_BUFFERS` + per-request hot-path cuts** (skip no-op interceptor vtable calls, gate the speed-controller): **no measurable effect on the large-body gap** — 256 KB stayed at −35%. This **falsifies the "read-overhead/buffer-size" hypothesis**: `SSL_read` caps at one ~16 KB record per call, so a bigger caller buffer doesn't reduce the call count, and reducing it (6.4b) didn't help. The gap is **throughput/data-path bound, not call-overhead bound**. (These changes are correctness-neutral and low-risk; kept as hygiene.)

## Concurrency (Phase 2) — the apparent win, and why it was an artifact

Added a concurrent bench mode (`BENCH_CONCURRENCY=K`) with a **fair** baseline: K OS threads, each its own libcurl `Easy` handle (keep-alive). 8-core board:

| K | ylong vs libcurl |
|---|------------------|
| 1 | +0.3% |
| 2 | −6% |
| 4 | −28% |
| **8** | **+26%** (stable across runs) |
| 16 | +14% |

The +26% at K=8 *appeared* to meet ≥20% — but the curve is **non-monotonic** (behind at K=4, ahead at K=8), which pointed to a **co-location confound**: in this single-machine loopback bench the ylong client shares one tokio runtime with the proxy+origin fixtures, while the libcurl client's K blocking OS threads **oversubscribe** against the fixtures' separate 8-thread runtime (≈16 threads on 8 cores at K=8). The "win" was scheduling artifact, not client efficiency.

## Rigorous test — process-isolated, CPU-pinned (the defensible number)

`BENCH_ROLE=server|client`: fixtures run in a **separate process pinned to cores 0–3** (`taskset`), client pinned to cores 4–7. Both clients then hit an identical isolated server.

| K (client on 4 cores) | ylong vs libcurl (isolated) |
|---|---|
| 1 | −0.8% / +0.2% → **parity** |
| 2 | +0.2% / +0.0% → **parity** |
| 4 | **−16.6% / −12.5%** → ylong behind |

**The +26%@K=8 disappears once the confound is removed.** ylong is at parity at low concurrency and ~−14% when the client cores are saturated.

## Root cause (perf) — why, definitively

Profiled the 256 KB case (server in a separate process) with `perf`:

- **Same cipher**: both negotiate `TLSv1.2 / ECDHE-RSA-CHACHA20-POLY1305`; `perf` shows the identical `EVP_DecryptUpdate` (ChaCha20) symbol at ~5.7% for both. Crypto ruled out.
- **Same work**: instructions ≈ equal (ylong 21.31 B vs libcurl 21.12 B).
- **The difference is context-switches**: `perf stat` — ylong **110,794** vs libcurl **3,407** (≈33×, ~37/req vs ~1/req), giving ylong lower IPC (1.27 vs 1.42) and +13% cycles / +18% CPU-time.

Mechanism (code-confirmed): ylong's async readiness I/O parks on `Poll::Pending` whenever the socket returns `WouldBlock` (`ssl_stream/wrapper.rs` → `bio.rs` `SHOULD_RETRY` → `SSL_read` `WANT_READ` → `Pending`); on the **multi-thread** runtime each re-wake is a cross-thread scheduler hand-off (context-switch). The **nested TLS-in-TLS** proxy path doubles it (each wake re-drives two `SSL_read` state machines). libcurl does a blocking `read()` loop on one thread → ~0 switches per record.

**Validation:** switching ylong to a **current-thread runtime** (`BENCH_RT=current`) collapses context-switches **110,794 → 4,328** (≈ libcurl's 3,407) — confirming the multi-thread cross-thread wake is the cause.

## Final verdict — honest (revised after perf)

- **In a fair, non-CPU-contended test (server isolated in its own process, ample cores), `ylong_http_client` is at PARITY with libcurl — including single-connection AND 256 KB large bodies (+0.7% / +1.3%).** The earlier **−35% (large body), −14% (concurrency), +26% (K=8)** figures were all **CPU-contention / co-location artifacts** (client and server sharing one runtime/cores), not real client deficits — now retracted.
- **The "≥20% over libcurl" goal is NOT achievable** in any fair configuration: the honest result is **parity**. Both are OpenSSL-bound on the same TLS-in-TLS path with the same cipher and the same instruction count.
- **ylong's one real CPU overhead** vs libcurl is **~33× context-switches** from the multi-thread async runtime's cross-thread wakes per I/O readiness event. It only costs wall-clock under **CPU saturation** (co-located, or concurrency ≈ cores, where it shows as ~−14%); with spare cores ylong reaches parity despite it.

**Actionable optimizations (reach parity under load, not +20%):**
- **Use a current-thread runtime (or pin a connection's task to one worker)** for few-connection workloads — collapses the cross-thread wakes to libcurl level (measured 110k→4k). This is the highest-impact lever and is largely a *runtime/usage* choice.
- Drain the socket fully per wake and buffer the inner proxy-TLS layer to cut the nested-TLS double-yield (library change, moderate).
- Connection-pool serialization under concurrency (`util/pool.rs` global mutex + `exist_h1_conn` take-all rebuild).

ylong's async model's true advantage is **multiplexing many connections on few threads** (where libcurl would need many OS threads), not single-connection throughput — and fixing the per-connection context-switch waste above is exactly what makes that concurrent case scale.
