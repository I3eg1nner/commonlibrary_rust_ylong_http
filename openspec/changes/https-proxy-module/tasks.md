## 1. Prepare TLS stream for nesting

- [x] 1.1 Audit `async_impl/ssl_stream/` and `sync_impl/ssl_stream.rs` to confirm whether the SSL stream is generic over its inner transport or hardcoded to `TcpStream` — both are already generic (`AsyncSslStream<S>`, `SslStream<S>`); `Ssl::connect<S>` is generic too.
- [x] 1.2 Generalize the async SSL stream to wrap any `AsyncRead + AsyncWrite` inner stream — already generic; introduced `ProxyTunnel` (impls `AsyncRead`/`AsyncWrite`) so the origin TLS layer wraps it uniformly. `MixStream::Https` now holds `AsyncSslStream<ProxyTunnel>`.
- [x] 1.3 Generalize the sync SSL stream to wrap any `Read + Write` inner stream — already generic; sync `ProxyTunnel` impls `Read`/`Write`; `MixStream<ProxyTunnel>`.
- [x] 1.4 TLS-in-TLS nesting is exercised by the `sdv_async_https_proxy_success` integration test (origin `AsyncSslStream` nested over a proxy `AsyncSslStream` via `ProxyTunnel::Tls`) against loopback TLS proxy + origin servers — passes.

## 2. Extract the proxy module

- [x] 2.1 Create a dedicated proxy module housing the connector-agnostic connect/tunnel abstraction — `async_impl/proxy.rs` and `sync_impl/proxy.rs` with the `TunnelConnect` trait; selection types stay in `util/proxy.rs`.
- [x] 2.2 Implement plaintext CONNECT/tunnel behavior — `HttpProxyTunnel` + `connect_tunnel` (request line, headers, `Proxy-Authorization`, 200/407/headers-too-long/unsuccessful handling). Tunnel unit tests relocated and passing.
- [x] 2.3 Switch `async_impl/connector/mod.rs` to delegate tunnel establishment to the proxy module (`ProxyKind` + `TunnelConnect`) instead of inline `tunnel()`.
- [x] 2.4 Switch `sync_impl/connector.rs` to delegate to the proxy module — code complete; sync now compiles and is tested end-to-end (the pre-existing `sync_impl`/runtime breakage was fixed, see group 8).
- [x] 2.5 Preserve scheme-based proxy matching, no-proxy (wildcard/domain) rules, and basic auth — `util/proxy.rs` selection logic unchanged; its tests pass.
- [x] 2.6 Proxy selection compiles without TLS for plaintext proxies; the TLS tunnel abstraction is `__tls`-gated (tunneling only occurs for HTTPS targets). The no-tls crate build (previously broken on Linux by a `use libc` gating bug) is now fixed — see 8.6.
- [x] 2.7 Run existing tests to confirm behavior parity — full lib suite passes (136/136) on async + tls + ylong_base.

## 3. Proxy-server TLS configuration surface

- [x] 3.1 Add an optional proxy-scoped `TlsConfig` to `ProxyInfo` (`proxy_tls`), reaching `ConnectorConfig` via `ConnectorConfig.proxies` (feature-gated by `__tls`).
- [x] 3.2 Add an additive `ProxyBuilder::tls_config(TlsConfig)` entry. Per design decision D6, the granular controls (CA roots, client identity, min/max version, cipher list) are reached by building the `TlsConfig` with the existing public `TlsConfig::builder()` rather than duplicating the whole builder surface on `ProxyBuilder`. Added the missing `TlsConfigBuilder::private_key_file` (+ FFI `SSL_CTX_use_PrivateKey_file`/`SSL_CTX_check_private_key` and `SslContextBuilder::set_private_key_file`) so a client cert **and private key** can be set — required for mutual TLS.
- [x] 3.3 Proxy verification toggles (accept-invalid-certs/hostnames, SNI) are scoped to the proxy via the proxy's own `TlsConfig`, independent of the origin `TlsConfig`.
- [x] 3.4 Treat an `https://` proxy URL as implying TLS-to-proxy (`ProxyInfo::is_tls` = scheme is HTTPS or a proxy `TlsConfig` is set); explicit config refines it, default config used otherwise.
- [x] 3.5 Wire proxy TLS config from `ProxyBuilder` through `ClientBuilder` into `ConnectorConfig` — automatic, since the proxy carries its `TlsConfig` into `ConnectorConfig.proxies`.

## 4. HTTPS proxy connection (TLS-in-TLS)

- [x] 4.1 Implement `HttpsProxyTunnel` (feature-gated): establish TLS to the proxy using the proxy `TlsConfig` before sending any CONNECT/credentials.
- [x] 4.2 Send CONNECT + `Proxy-Authorization` over the proxy TLS session; non-200 (407 etc.) maps to a `Connect`-kind error and skips the origin handshake.
- [x] 4.3 After 200, perform the origin TLS handshake nested over the proxy TLS stream — `MixStream::Https(AsyncSslStream<ProxyTunnel::Tls(..)>)`.
- [x] 4.4 Support one-way (CA-validated proxy cert) and mutual TLS (client cert/key) to the proxy via the proxy-scoped `TlsConfig` — both verified by integration tests (`sdv_async_https_proxy_mtls_success` / `_mtls_missing_cert_rejected`).
- [x] 4.5 Implement the async path end-to-end through the connector — verified by compile + example + tunnel unit tests.
- [x] 4.6 Implement the sync path end-to-end through the connector — verified by `sdv_sync_https_proxy_success` (real TLS-in-TLS through the sync client).
- [x] 4.7 Proxy connections are pooled/kept alive via the existing connection pool keyed by proxy address, amortizing the proxy TLS handshake — inherited, no new code required.

## 5. Tests

- [x] 5.1 Add a local TLS-secured proxy test harness — `tests/sdv_async_https_proxy.rs`: an OpenSSL TLS-terminating CONNECT proxy fixture (`run_tls_proxy`) + a TLS origin server, reusing the existing `tests/file` cert fixtures.
- [x] 5.2 Test: HTTPS request through HTTPS proxy succeeds (async **and** sync) — `sdv_async_https_proxy_success` + `sdv_sync_https_proxy_success` both pass (real TLS-in-TLS).
- [x] 5.3 Test: proxy credentials only transmitted inside the proxy TLS session — `sdv_async_https_proxy_auth_in_tls`: the proxy captures the `CONNECT` head *after* TLS termination and asserts it carries `Proxy-Authorization`.
- [x] 5.4 Test: untrusted proxy cert rejected for one-way verification — `sdv_async_https_proxy_untrusted_cert_rejected` (proxy `TlsConfig` not trusting the CA fails the handshake). Trusted case covered by 5.2.
- [x] 5.5 Test: mutual TLS to proxy — `sdv_async_https_proxy_mtls_success` (proxy requires a client cert; client presents `cert.pem`+`key.pem` via the proxy `TlsConfig`) and `sdv_async_https_proxy_mtls_missing_cert_rejected` (no client cert → handshake rejected). Reuses existing fixtures (the leaf cert/key double as the client identity, both chaining to `root-ca.pem`).
- [ ] 5.6 Test: proxy TLS version/cipher restrictions — not added; needs a proxy fixture pinned to a single version/cipher. The version/cipher *configuration* is exercised by `min_proto_version`/`cipher_list` on the proxy `TlsConfig`; escape-hatch scoping is covered by 5.4 (proxy verification independent of origin).
- [x] 5.7 Test: CONNECT 407/non-200 surfaces a connection error and skips the origin handshake — `sdv_async_https_proxy_407_rejected` passes.
- [x] 5.8 Add an example demonstrating HTTPS-proxy usage — `examples/async_proxy_https.rs` (registered in `Cargo.toml`, compiles), showing `Proxy::all("https://...").tls_config(..).basic_auth(..)` and an HTTPS origin.

## 6. Performance: benchmark and optimization

- [x] 6.1 Build a reproducible HTTPS-proxy benchmark — `benches/https_proxy_bench.rs` (`harness = false`): TLS proxy + TLS origin fixtures, fixed documented config (requests/warmup/payload, keep-alive sequential).
- [x] 6.2 libcurl baseline — **two baselines** in `benches/https_proxy_bench.rs`: (a) **libcurl the library** via the `curl` crate, in-process, one reused `Easy` handle (keep-alive), same system OpenSSL, identical TLS verification — this is the correct library-vs-library comparison; (b) the `curl` CLI as a reference-only line.
- [x] 6.3 Capture metrics for both clients — bench prints ylong, libcurl(library), and curl(CLI) req/s + the library delta.
- [ ] 6.4 Apply targeted optimizations — refined from a fine-grained vs-libcurl breakdown (RISC-V). Findings: steady-state small-msg keep-alive is at parity/slight-win (+2%); the deficits are **cold-connection setup (−40%)** and **large-body throughput (−22%)**. Prioritized plan:
  - [ ] 6.4a **[high] TLS session resumption (proxy + origin)** — enable the OpenSSL `SSL_CTX` session cache and reuse `SSL_SESSION` within a client/pool so reconnects use abbreviated handshakes (libcurl already does this within a handle). Targets the −40% cold-connect gap (the feature's own TLS-in-TLS handshake path). Verify with `BENCH_KEEPALIVE=0`.
  - [ ] 6.4b **[high] Large-body read efficiency** — increase the body/TLS read chunk size and minimize copies across the `ProxyTunnel → AsyncSslStream → MixStream → body reader` layers (read straight into the caller buffer; avoid intermediate `Vec`). Targets the −22% 256 KB gap. Verify with `BENCH_PAYLOAD=262144`.
  - [ ] 6.4c **[med] Reuse CONNECT handshake buffers** — in `connect_tunnel`, avoid the per-tunnel `Vec::new()` + `[0u8; 8192]`; build the CONNECT request once and read the reply into a small reusable buffer. Minor cold-connect latency.
  - [ ] 6.4d **[med] Guarantee TCP_NODELAY on the tunnel sockets** — confirm nodelay on the proxy hop; prevents Nagle/delayed-ACK stalls (the ~40 ms 16 KB stall seen in the fixture). Also set nodelay on the bench fixture's server/upstream sockets to de-noise large-payload measurement.
  - Honest expectation: steady-state is already on par with libcurl; the realistic outcome is to **erase the cold-connect / large-body deficits (reach parity-to-slight-win across the board)**, NOT to beat a mature C library by 20% on an OpenSSL-bound path. The ≥20% figure only holds vs the `curl` CLI tool, which must be labeled as a tool (not library) comparison.
- [ ] 6.5 Certify ≥20% over **libcurl (the library)** — **NOT MET.** RISC-V (SpacemiT K3, rustc 1.96, same system OpenSSL), 5 runs: ylong ~4,310 vs libcurl-library ~4,237 req/s = **≈ +1.5% (range +0.6%…+2.2%)** — essentially on par, far below 20%. The earlier "+26% / +41.5%" were vs the `curl` **CLI** (process/CLI overhead), not the library, and do not represent a real advantage. Both clients are OpenSSL-bound on the same TLS-in-TLS path. (See `benchmark-results.md`.)
- [ ] 6.6 Re-run section 5 tests after optimization to confirm no regression — pending 6.4.

## 7. Validation and docs

- [x] 7.1 `cargo fmt` applied; `cargo clippy` clean (warnings only, consistent with existing style); lib + integration tests pass on async×tls (tokio + ylong_base) and sync×tls (tokio); **all of async-only, sync-only, async+sync, and no-tls builds now compile** (async/sync × tls-on/off). One pre-existing sync lib test (`ut_tls_ssl_verify_hostname`) fails because it connects to the external `huawei.com:443`, whose certificate is reported expired in this environment — not related to this change.
- [x] 7.2 Proxy module abstraction + "how to add a new proxy protocol" documented as module-level rustdoc in `async_impl/proxy.rs` and `sync_impl/proxy.rs` (implement `TunnelConnect`; the connector is unchanged).
- [x] 7.3 Public proxy-TLS API documented via `ProxyBuilder::tls_config` rustdoc + the `async_proxy_https` example; benchmark methodology + (indicative) results recorded in `benchmark-results.md`.
- [x] 7.4 Run `openspec validate https-proxy-module` and resolve any issues — change validates clean.

## 8. Fix pre-existing sync_impl breakage (enables the sync HTTPS-proxy path)

- [x] 8.1 `sync_impl/client.rs`: add the missing `timeout` (and feature-gated `fchown`) fields when constructing `ConnectorConfig` (mirrors the async client).
- [x] 8.2 `sync_impl/pool.rs`: update the `Pool::get` call and `Conns::new` to the current 4-arg / `(usize, SpeedConfig)` signature.
- [x] 8.3 `util/interceptor/mod.rs`: feature-gate the `async_impl`-typed imports and the `Request`/`Response`/`HttpBody` interceptor methods behind `#[cfg(feature = "async")]` so the shared module compiles for sync-only builds.
- [x] 8.4 `lib.rs` runtime module: export `Semaphore`/`SemaphorePermit`/`sleep`/`Sleep` under `tokio_base` (not only `tokio_base + async`), since the shared dispatcher and rate limiter need them in sync builds too.
- [x] 8.5 Verify no async regression — async lib (107) + async HTTPS-proxy tests (6) still pass; sync lib (152) + sync HTTPS-proxy test pass.
- [x] 8.6 Fix the pre-existing no-tls Linux build break: gate `use libc::{gid_t, uid_t}` in `async_impl/connector/mod.rs` and `async_impl/dns/happy_eyeballs.rs` with the same `#[cfg(all(target_os = "linux", feature = "ylong_base", feature = "__tls"))]` as their only usage. All no-tls combos (async/sync/both) now compile.
- [x] 8.7 Add `TlsConfigBuilder::private_key_file` + FFI (`SSL_CTX_use_PrivateKey_file`, `SSL_CTX_check_private_key`) + `SslContextBuilder::set_private_key_file` so a client certificate's private key can be loaded — without it, mutual TLS (子任务1 双向证书验证 / 客户端私钥) was not actually achievable. Verified by the mTLS integration tests.
