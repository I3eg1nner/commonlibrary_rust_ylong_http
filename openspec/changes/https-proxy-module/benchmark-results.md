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

## Notes / headroom

- ylong's speed comes from the existing connection pool (keep-alive amortizes the
  proxy TLS handshake). No HTTPS-proxy-specific micro-optimizations (buffer reuse,
  batched CONNECT writes, inter-layer copy elimination — task 6.4) have been
  applied; those are the remaining headroom if the ≥20%-over-libcurl goal is to be
  pursued, though beating a mature C library by 20% on an OpenSSL-bound path is
  ambitious.
- The x86-sandbox numbers were CLI-based and are superseded by this
  library-vs-library measurement; they are not a valid basis for the target.
