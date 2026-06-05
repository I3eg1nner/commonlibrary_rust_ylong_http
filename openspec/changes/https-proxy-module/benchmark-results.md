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

## Results

### Indicative run (shared development sandbox — NOT representative)

| Client | Time (2000 req) | Throughput | Latency |
|--------|-----------------|-----------|---------|
| ylong_http_client | 0.159 s | 12,616 req/s | 0.079 ms/req |
| libcurl (`--http1.1`) | 0.271 s | 7,385 req/s | 0.135 ms/req |
| **Δ throughput** | | **+41.5%** | |

> ⚠️ Measured on a shared sandbox. The `curl` leg reuses a single process/tunnel
> for all 2000 requests (so process startup is amortized) and is pinned to
> HTTP/1.1 to match ylong. The result clears the ≥20% target *here* and the
> comparison is conservative (ylong verifies the proxy cert; curl does not), but
> a shared host is still **not** a valid environment to formally certify the
> criterion — re-run on representative hardware.

### Certification on representative hardware — RISC-V (SpacemiT K3) — ✅ MEETS ≥20%

Run natively on a RISC-V development board, which is representative of
OpenHarmony targets:

- **Hardware**: SpacemiT K3, RISC-V64 (`riscv64gc`), 8 cores, 7.7 GB RAM
- **OS**: Bianbu 4.0 (Ubuntu-based)
- **Toolchain**: rustc 1.96.0 stable, `bench` profile (optimized)
- **OpenSSL**: system OpenSSL 3.5 (same library linked by both `ylong` and `curl 8.18`, so the comparison is fair)
- Same fixed configuration as above (2000 req, 200 warm-up, 1 KB, keep-alive, HTTP/1.1).

Five consecutive runs (very low variance):

| Run | ylong req/s | libcurl req/s | Δ throughput |
|-----|-------------|---------------|--------------|
| 1 | 4,278 | 3,172 | +25.9% |
| 2 | 4,353 | 3,203 | +26.4% |
| 3 | 4,376 | 3,199 | +26.9% |
| 4 | 4,355 | 3,217 | +26.1% |
| 5 | 4,339 | 3,192 | +26.4% |
| **median** | **~4,350** | **~3,200** | **+26.4%** (range 25.9–26.9%) |

**Conclusion:** on representative RISC-V hardware, `ylong_http_client` is
consistently **~26% faster** than `libcurl` in the HTTPS-proxy scenario,
comfortably and reproducibly clearing the **≥20%** target.

> Note: this still uses the `curl` CLI (one process reused across all 2000
> requests, so startup is amortized). The margin is smaller than on the x86
> sandbox (+41.5%), as expected for different CPU characteristics, but the target
> is met on both.

## Notes

- The current ylong performance benefits from the existing connection pool
  (keep-alive amortizes the proxy TLS handshake). No HTTPS-proxy-specific
  micro-optimizations (buffer reuse, batched CONNECT writes, inter-layer copy
  elimination — task 6.4) have been applied yet; those remain available headroom.
