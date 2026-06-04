## Why

`ylong_http_client` today only supports plaintext (HTTP) proxy servers: the CONNECT tunnel for HTTPS targets is always opened over an unencrypted TCP connection to the proxy. This leaves proxy credentials and CONNECT metadata exposed on the wire and prevents use in environments that mandate a TLS-secured ("HTTPS") proxy. The proxy logic is also entangled with the connector implementation, making it hard to add new proxy protocols. Finally, the current HTTPS-over-proxy path has not been tuned against `libcurl`.

This change adds first-class HTTPS proxy support, extracts proxy handling into a dedicated extensible module, and tunes the HTTPS-proxy connection path for performance.

## What Changes

- Add support for connecting to a **TLS-secured proxy server** ("HTTPS proxy"): establish a TLS session to the proxy first, then issue the CONNECT tunnel and the inner target TLS session over it (TLS-in-TLS), for both async and sync clients.
- Use the existing OpenSSL (`c_openssl`) backend to provide the proxy-side TLS capability — no new TLS dependency.
- Add **proxy-server TLS verification** controls: one-way (verify proxy server cert against CA) and mutual/two-way (present client cert to proxy) verification, independent of the verification settings used for the target server.
- Add a **proxy-specific TLS configuration** surface: CA certificates, client certificate + private key, min/max protocol version, cipher suites, SNI/hostname-verification toggles, and accept-invalid-cert escape hatches — mirroring the target-server TLS builder but scoped to the proxy connection.
- Extract the proxy routing/selection/tunnel logic out of the connector into a dedicated **proxy module** with a connector-agnostic abstraction (a proxy "connect" trait) so new proxy schemes (e.g. SOCKS) can be added without touching the HTTP connector. **BREAKING** only if internal `pub(crate)` proxy types are re-exported downstream; the public builder API stays source-compatible and is extended additively.
- Add a **performance benchmark harness** comparing the HTTPS-proxy path against `libcurl`, and apply targeted optimizations (buffer reuse, reduced syscalls/allocations on the tunnel + handshake path, connection reuse) to reach the ≥20% throughput/latency improvement target in the HTTPS-proxy scenario.

## Capabilities

### New Capabilities
- `https-proxy-tls`: Connecting through a TLS-secured proxy server, including establishing TLS to the proxy, CONNECT tunneling over that TLS session, and the inner target TLS handshake (TLS-in-TLS).
- `proxy-tls-config`: Public configuration API for proxy-server TLS — one-way/two-way certificate verification, client certificate & private key, CA roots, protocol versions, cipher suites, SNI and hostname verification.
- `proxy-module`: An extracted, extensible proxy module decoupling proxy selection, authentication, and tunnel establishment from the HTTP connector, with an abstraction that supports adding new proxy protocols.
- `https-proxy-performance`: A benchmark methodology and performance budget for the HTTPS-proxy path versus libcurl, with the ≥20% improvement target as an acceptance criterion.

### Modified Capabilities
<!-- No existing specs in openspec/specs/; nothing to modify. -->

## Impact

- **Affected code (ylong_http_client crate):**
  - `src/util/proxy.rs` — proxy types (`Proxy`, `ProxyInfo`, `Intercept`), routing; gains proxy TLS config + new module surface.
  - `src/util/config/settings.rs` — public `Proxy`/`ProxyBuilder` API; new proxy-TLS builder methods.
  - `src/util/config/connector.rs` — `ConnectorConfig` carries proxy TLS config.
  - `src/util/config/tls/` — reuse `TlsConfigBuilder`/`TlsConfig` for proxy scope.
  - `src/async_impl/connector/mod.rs` and `src/sync_impl/connector.rs` — `tunnel()` / `https_connect()` to layer TLS-to-proxy before CONNECT; optimization changes.
  - `src/async_impl/client.rs` / `sync_impl/client.rs` — `ClientBuilder` wiring for proxy TLS.
  - New module (e.g. `src/util/proxy/` or `async_impl/proxy/`) housing the extracted connector-agnostic proxy connect abstraction.
- **APIs:** Additive public builder methods on `Proxy`/`ProxyBuilder` (e.g. proxy TLS config); no removal of existing methods.
- **Dependencies:** OpenSSL via existing `__tls` / `__c_openssl` features; no new third-party crate. Benchmark harness adds a dev/bench-only dependency on a local `libcurl`/`curl` for comparison (not a runtime dependency).
- **Features:** New behavior gated behind existing `__tls` feature; proxy module available without TLS for plain HTTP proxies.
- **Compatibility:** Existing HTTP-proxy and direct-HTTPS behavior unchanged; new HTTPS-proxy behavior is opt-in via builder configuration.
