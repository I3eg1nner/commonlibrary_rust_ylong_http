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

### Certification (representative hardware) — PENDING

The official ≥20% target must be measured on representative hardware, ideally
comparing against an in-process libcurl driver (not the `curl` CLI) to remove
process-startup overhead. Record the certified numbers here when available.

## Notes

- The current ylong performance benefits from the existing connection pool
  (keep-alive amortizes the proxy TLS handshake). No HTTPS-proxy-specific
  micro-optimizations (buffer reuse, batched CONNECT writes, inter-layer copy
  elimination — task 6.4) have been applied yet; those remain available headroom.
