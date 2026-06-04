## Context

`ylong_http_client` is a Rust HTTP client supporting HTTP/1.1, HTTP/2, and HTTP/3, with both async (tokio/ylong_runtime) and sync implementations. TLS is provided through an OpenSSL FFI backend (`src/util/c_openssl`), gated by the `__tls` / `__c_openssl` features.

Current proxy handling:
- Proxy types live in `src/util/proxy.rs` (`Proxies`, `Proxy`, `Intercept`, `ProxyInfo`); public builder API in `src/util/config/settings.rs`.
- The connector (`src/async_impl/connector/mod.rs`, `src/sync_impl/connector.rs`) inlines tunnel logic: for an HTTPS origin behind a proxy it opens a **plaintext** TCP socket to the proxy, sends `CONNECT host:port HTTP/1.1` (+ optional `Proxy-Authorization`), reads the `200`, then performs the origin TLS handshake directly over that socket.
- There is no way to TLS-secure the proxy hop itself; CONNECT and credentials travel in cleartext.

Constraints:
- Reuse the existing OpenSSL backend; no new TLS crate.
- Public builder API must stay source-compatible; new methods are additive.
- Must work for both async and sync clients and across enabled HTTP versions.
- TLS code must remain behind `__tls`.

Stakeholders: client maintainers, downstream OpenHarmony consumers configuring corporate/secured proxies.

## Goals / Non-Goals

**Goals:**
- Support TLS-secured proxy servers: TLS-to-proxy, then CONNECT, then nested TLS-to-origin (TLS-in-TLS).
- Independent proxy-scoped TLS configuration (CA, client cert/key, versions, ciphers, SNI, verification toggles), one-way and mutual.
- Extract proxy logic into a dedicated, extensible module with a connector-agnostic abstraction so new proxy protocols (e.g. SOCKS) can be added later without editing the connector.
- Provide a reproducible HTTPS-proxy benchmark vs libcurl and reach ≥20% improvement on the primary metric.

**Non-Goals:**
- Implementing SOCKS or other new proxy protocols (only making the abstraction support them).
- Proxy auto-discovery (PAC/WPAD) or system-proxy detection.
- Proxy chaining (multiple proxies in sequence).
- Changing origin-server TLS behavior or the public TLS builder semantics for origins.

## Decisions

### D1: Represent the proxy hop as an optional separate TLS layer, not a new `Intercept` variant

`Intercept` currently describes which **request** scheme a proxy applies to (`Http`/`Https`/`All`), not the proxy's own transport. Overloading it would conflate "what traffic to proxy" with "is the proxy itself TLS". Instead, attach an optional proxy-TLS configuration to the proxy entry (`ProxyInfo` / `Proxy`), and decide "TLS to proxy" from (a) the proxy URL scheme being `https` and/or (b) presence of a proxy TLS config.

- **Alternative considered:** add `Intercept::HttpsProxy`. Rejected — semantically overloads an enum about target scheme, and breaks the matching logic that selects proxies by request scheme.

### D2: Reuse `TlsConfig` / `TlsConfigBuilder` for the proxy scope

The existing `TlsConfigBuilder` already exposes CA files, client cert/chain + key, min/max version, cipher list, SNI, hostname/cert verification toggles, and pinning. Wrap a second instance of this for the proxy. `ConnectorConfig` gains an optional `proxy_tls: Option<TlsConfig>` (feature-gated), and the proxy module builds the proxy `Ssl` from it.

- **Alternative considered:** a brand-new minimal proxy-TLS struct. Rejected — duplicates a mature surface and would drift from the origin TLS feature set; the requirements explicitly ask for parity (versions, ciphers, mutual auth).

### D3: Public API — extend `ProxyBuilder` with proxy TLS methods

Add additive builder methods, e.g. `ProxyBuilder::tls_config(TlsConfig)` / focused helpers (`proxy_ca_file`, `proxy_identity(cert, key)`, `proxy_min_tls_version`, `proxy_cipher_list`, `danger_accept_invalid_proxy_certs`, ...) that funnel into a proxy-scoped `TlsConfigBuilder`. The proxy URL may be given as `https://...` to imply TLS-to-proxy. No existing method changes signature.

- **Alternative considered:** configure proxy TLS on `ClientBuilder` globally. Rejected — proxy TLS is per-proxy and must be independent from origin TLS (proxy-tls-config requirement); keeping it on the proxy entry keeps scope correct and supports per-proxy settings.

### D4: Extract a `proxy` module with a `ProxyConnector`/tunnel abstraction

Introduce a module (e.g. `src/util/proxy/` for shared types + a connect trait, with connector-side glue in async/sync impls) defining something like:

```
trait ProxyConnect {
    // Given an established byte stream to the proxy, produce a stream to the origin
    // (perform TLS-to-proxy if needed, then CONNECT/tunnel).
    async fn connect_through(&self, raw: Stream, target: &Uri, auth: Option<Header>) -> Result<Stream>;
}
```

Implementations: `HttpProxyConnect` (today's plaintext CONNECT) and `HttpsProxyConnect` (TLS-to-proxy wrapper around the CONNECT, feature-gated). The connector calls `proxy_module::select(uri)` then `connect_through(...)`, and is otherwise agnostic to the scheme. Async and sync get parallel trait variants matching their stream types.

- **Alternative considered:** keep logic inline but add an `if proxy_tls` branch. Rejected — fails the extensibility requirement and keeps the connector growing; the abstraction is the deliverable, not just HTTPS.

### D5: TLS-in-TLS via stacked `SslStream`

For an HTTPS origin via HTTPS proxy: build `outer = SslStream(proxy_cfg, TcpStream)`; handshake; write CONNECT + read 200 over `outer`; then `inner = SslStream(origin_cfg, outer)`; handshake. The existing `AsyncSslStream`/sync ssl stream already wrap an arbitrary `AsyncRead+AsyncWrite` (or `Read+Write`) inner, so nesting requires the SSL stream to be generic over its inner stream rather than hardcoded to TCP — verify/adjust the stream type bounds.

- **Risk surfaced here:** if the ssl stream type is hardcoded to `TcpStream`, it must be generalized; this is the main structural change. Tracked in tasks.

### D6: Performance approach — measure first, then targeted optimization

Build the benchmark + libcurl baseline before optimizing. Candidate optimizations on the HTTPS-proxy path: reuse read/write buffers across the tunnel handshake (avoid per-CONNECT allocation), minimize syscalls (vectored/batched writes for CONNECT request line+headers), ensure proxy connections are pooled/kept alive so the TLS-to-proxy handshake is amortized across requests, and avoid redundant copies between the nested TLS layers. Validate the ≥20% target against libcurl under a fixed config; record results.

- **Alternative considered:** optimize speculatively. Rejected — without the libcurl baseline harness we cannot prove the 20% target nor avoid regressions.

## Risks / Trade-offs

- **SSL stream not generic over inner transport** → If `AsyncSslStream`/sync variant is tied to `TcpStream`, TLS-in-TLS is impossible without refactor. → Generalize the inner-stream type parameter early (first implementation task); add a nesting unit test.
- **TLS-in-TLS performance overhead** → Double encryption could make the 20% target harder. → Amortize the proxy handshake via connection pooling, reduce copies, and benchmark; the target is for the documented scenario, which permits keep-alive.
- **Feature-flag matrix complexity** (`async`/`sync` × `__tls` × HTTP versions) → broken builds in some combos. → CI-style local checks for `--no-default-features` + relevant combos; keep all proxy-TLS code behind `__tls`.
- **Mutual-auth (mTLS) misconfiguration surfaced as opaque handshake errors** → poor UX. → Map proxy handshake failures to a distinct proxy-connection error variant (per https-proxy-tls spec).
- **Benchmark environment variance** vs libcurl → unfair/unreproducible comparison. → Fix versions, ciphers, payload, concurrency, warm-up; document methodology; run both clients on the same host/network.
- **API surface creep** from many focused proxy-TLS methods → Prefer a single `ProxyBuilder::tls_config(TlsConfig)` entry plus a few common shortcuts; reuse `TlsConfigBuilder` rather than re-inventing.

## Migration Plan

1. Generalize the SSL stream over its inner transport (enabling nesting); add a nesting test. No behavior change.
2. Land the extracted proxy module with `HttpProxyConnect` reproducing current behavior; switch the connector to call through it (behavior-parity, covered by existing proxy tests).
3. Add `proxy_tls` to `ConnectorConfig` and the `HttpsProxyConnect` implementation, gated by `__tls`.
4. Add additive `ProxyBuilder` proxy-TLS methods and wire through `ClientBuilder`.
5. Add the benchmark harness + libcurl baseline; optimize; record results.

Rollback: each step is additive/behavior-preserving; reverting steps 3–5 leaves the extracted-but-equivalent proxy module (step 2) intact. The new behavior is opt-in via configuration, so disabling it requires no code rollback for existing users.

## Open Questions

- Should an `https://` proxy URL alone imply TLS-to-proxy, or must a proxy TLS config be explicitly set? (Proposed: scheme implies it; config refines it.)
- Do we need HTTP/2 CONNECT (extended CONNECT) to the proxy, or is HTTP/1.1 CONNECT sufficient for the tunnel? (Proposed: HTTP/1.1 CONNECT for the tunnel hop, independent of origin HTTP version.)
- Exact benchmark workload to certify the 20% figure (payload size, concurrency level) — to be fixed in the performance tasks.
