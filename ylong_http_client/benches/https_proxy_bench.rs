// Copyright (c) 2024 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! HTTPS-proxy performance benchmark harness: `ylong_http_client` vs `libcurl`.
//!
//! Topology: client --TLS--> HTTPS proxy --CONNECT tunnel--> origin HTTPS
//! server. Both clients run the identical scenario (same proxy, same origin,
//! same keep-alive sequential workload) so the numbers are comparable.
//!
//! Run with:
//!   OPENSSL_DIR=... RUSTFLAGS="-L <libdir> -l ssl -l crypto" \
//!     cargo bench --no-default-features \
//!     --features async,http1_1,tokio_base,tls_default --bench
//! https_proxy_bench
//!
//! Configuration is fixed and documented via the constants below. The `libcurl`
//! leg is skipped (with a printed note) if the `curl` binary is unavailable or
//! does not support HTTPS proxies.
//!
//! IMPORTANT: the printed improvement figure is only meaningful on a
//! representative host. A shared CI/sandbox machine is NOT a valid environment
//! to certify the >=20% target; re-run on representative hardware to validate.

#![cfg(all(
    feature = "async",
    feature = "http1_1",
    feature = "__tls",
    feature = "tokio_base"
))]

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use ylong_http::body::async_impl::Body as _;
use ylong_http_client::async_impl::{Body, ClientBuilder, Request};
use ylong_http_client::{Proxy, TlsConfig};

// ---- Benchmark configuration (env-overridable for parameter sweeps) ---------
// BENCH_REQUESTS (default 2000), BENCH_WARMUP (200), BENCH_PAYLOAD bytes (1024),
// BENCH_KEEPALIVE (1=reuse connection/tunnel, 0=new connection per request),
// BENCH_CONCURRENCY (default 1=sequential; K>1 runs K parallel workers, see main).
#[derive(Clone, Copy)]
struct Cfg {
    requests: usize,
    warmup: usize,
    payload: usize,
    keepalive: bool,
    concurrency: usize,
}

fn cfg() -> Cfg {
    let g = |k: &str, d: usize| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    Cfg {
        requests: g("BENCH_REQUESTS", 2000),
        warmup: g("BENCH_WARMUP", 200),
        payload: g("BENCH_PAYLOAD", 1024),
        keepalive: std::env::var("BENCH_KEEPALIVE")
            .map(|v| v != "0")
            .unwrap_or(true),
        concurrency: g("BENCH_CONCURRENCY", 1).max(1),
    }
}
// ----------------------------------------------------------------------------

fn file(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/file");
    p.push(name);
    p.to_str().unwrap().to_string()
}

fn tls_acceptor() -> Arc<SslAcceptor> {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor
        .set_private_key_file(file("key.pem"), SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_certificate_chain_file(file("cert.pem"))
        .unwrap();
    Arc::new(acceptor.build())
}

/// Loop-accepting origin HTTPS server; replies with a fixed-size payload and
/// keep-alive so a single connection serves many requests.
async fn serve_origin(listener: TcpListener, acceptor: Arc<SslAcceptor>, payload: usize) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        let _ = stream.set_nodelay(true);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let ssl = Ssl::new(acceptor.context()).unwrap();
            let mut stream = tokio_openssl::SslStream::new(ssl, stream).unwrap();
            if core::pin::Pin::new(&mut stream).accept().await.is_err() {
                return;
            }
            let _ = hyper::server::conn::Http::new()
                .http1_only(true)
                .http1_keep_alive(true)
                .serve_connection(
                    stream,
                    hyper::service::service_fn(move |_req| async move {
                        let body = vec![b'a'; payload];
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header("Content-Length", payload.to_string())
                                .body(hyper::Body::from(body))
                                .unwrap(),
                        )
                    }),
                )
                .await;
        });
    }
}

/// Loop-accepting TLS-terminating CONNECT proxy; tunnels each accepted client
/// connection to a fresh upstream TCP connection to the CONNECT target.
async fn serve_proxy(listener: TcpListener, acceptor: Arc<SslAcceptor>) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        let _ = stream.set_nodelay(true);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let ssl = Ssl::new(acceptor.context()).unwrap();
            let mut tls = tokio_openssl::SslStream::new(ssl, stream).unwrap();
            if core::pin::Pin::new(&mut tls).accept().await.is_err() {
                return;
            }
            let mut head = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = match tls.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                head.extend_from_slice(&tmp[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&head);
            let target = match text
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
            {
                Some(t) => t.to_string(),
                None => return,
            };
            if tls
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            if let Ok(mut upstream) = TcpStream::connect(target).await {
                let _ = upstream.set_nodelay(true);
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
            }
        });
    }
}

/// Builds a fresh ylong client configured for the HTTPS proxy. `max_h1_conn`
/// caps the H1 keep-alive connection pool size: K-way concurrency wants up to K
/// parallel tunnels, while the sequential path uses 1 (matching prior behavior).
fn ylong_client_k(proxy_addr: &str, max_h1_conn: usize) -> ylong_http_client::async_impl::Client {
    let proxy_tls = TlsConfig::builder()
        .ca_file(file("root-ca.pem"))
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();
    ClientBuilder::new()
        .tls_ca_file(&file("root-ca.pem"))
        .danger_accept_invalid_hostnames(true)
        .max_h1_conn_number(max_h1_conn)
        .proxy(
            Proxy::all(&format!("https://{proxy_addr}"))
                .tls_config(proxy_tls)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

/// Builds a fresh ylong client configured for the HTTPS proxy (sequential path).
fn ylong_client(proxy_addr: &str) -> ylong_http_client::async_impl::Client {
    ylong_client_k(proxy_addr, 1)
}

async fn ylong_once(client: &ylong_http_client::async_impl::Client, url: &str) {
    let req = Request::builder()
        .method("GET")
        .url(url)
        .body(Body::empty())
        .unwrap();
    let mut resp = client.request(req).await.expect("ylong request failed");
    let mut buf = [0u8; 16384];
    while resp.body_mut().data(&mut buf).await.unwrap() != 0 {}
}

/// Measures `ylong_http_client` over the HTTPS proxy. With `cfg.keepalive` the
/// connection/tunnel is reused (one client); otherwise a fresh client (hence a
/// fresh proxy TLS tunnel + origin handshake) is used for every request, which
/// isolates the connection-establishment cost.
async fn bench_ylong(cfg: Cfg, proxy_addr: String, origin_url: String) -> f64 {
    if cfg.keepalive {
        let client = ylong_client(&proxy_addr);
        for _ in 0..cfg.warmup {
            ylong_once(&client, &origin_url).await;
        }
        let start = Instant::now();
        for _ in 0..cfg.requests {
            ylong_once(&client, &origin_url).await;
        }
        start.elapsed().as_secs_f64()
    } else {
        for _ in 0..cfg.warmup {
            let client = ylong_client(&proxy_addr);
            ylong_once(&client, &origin_url).await;
        }
        let start = Instant::now();
        for _ in 0..cfg.requests {
            let client = ylong_client(&proxy_addr);
            ylong_once(&client, &origin_url).await;
        }
        start.elapsed().as_secs_f64()
    }
}

/// Measures the `curl` CLI tool (reference only — includes process/CLI overhead,
/// not a library comparison). Only meaningful with keep-alive (one process reuses
/// one tunnel across all URLs); returns `None` otherwise or if curl is missing.
fn bench_curl(cfg: Cfg, proxy_addr: &str, origin_url: &str) -> Option<f64> {
    if !cfg.keepalive {
        return None;
    }
    let probe = Command::new("curl").arg("--version").output().ok()?;
    if !probe.status.success() {
        return None;
    }
    let mut args: Vec<String> = vec![
        "-s".into(),
        "--http1.1".into(),
        "--proxy".into(),
        format!("https://{proxy_addr}"),
        "--proxy-insecure".into(),
        "--insecure".into(),
    ];
    for _ in 0..cfg.requests {
        args.push(origin_url.into());
    }
    let start = Instant::now();
    let status = Command::new("curl")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;
    let elapsed = start.elapsed().as_secs_f64();
    status.success().then_some(elapsed)
}

/// Measures **libcurl (the library)** over the same HTTPS proxy, driven in-process
/// via the `curl` crate's easy interface — the true library-vs-library comparison
/// (no `curl` CLI process / argument-parsing overhead). With `cfg.keepalive` a
/// single `Easy` handle reuses the connection/tunnel; otherwise each request forces
/// a fresh connection (`fresh_connect` + `forbid_reuse`), isolating setup cost.
///
/// TLS verification matches ylong exactly: proxy and origin certs verified against
/// the test root CA, hostname verification disabled.
fn libcurl_handle(origin_url: &str, proxy_addr: &str, keepalive: bool) -> Option<curl::easy::Easy> {
    use curl::easy::{Easy, HttpVersion};

    let ca = file("root-ca.pem");
    let mut h = Easy::new();
    h.url(origin_url).ok()?;
    h.proxy(&format!("https://{proxy_addr}")).ok()?;
    h.proxy_cainfo(&ca).ok()?;
    h.proxy_ssl_verify_peer(true).ok()?;
    h.proxy_ssl_verify_host(false).ok()?;
    h.cainfo(&ca).ok()?;
    h.ssl_verify_peer(true).ok()?;
    h.ssl_verify_host(false).ok()?;
    h.http_version(HttpVersion::V11).ok()?;
    if !keepalive {
        h.fresh_connect(true).ok()?;
        h.forbid_reuse(true).ok()?;
    }
    h.write_function(|data| Ok(data.len())).ok()?;
    Some(h)
}

fn bench_libcurl(cfg: Cfg, proxy_addr: &str, origin_url: &str) -> Option<f64> {
    let mut h = libcurl_handle(origin_url, proxy_addr, cfg.keepalive)?;

    for _ in 0..cfg.warmup {
        h.perform().ok()?;
    }
    let start = Instant::now();
    for _ in 0..cfg.requests {
        h.perform().ok()?;
    }
    Some(start.elapsed().as_secs_f64())
}

/// Splits `total` work items across `k` workers, giving the remainder to the
/// last worker. Returns the per-worker counts; their sum is exactly `total`.
fn split_work(total: usize, k: usize) -> Vec<usize> {
    let base = total / k;
    let mut counts = vec![base; k];
    if let Some(last) = counts.last_mut() {
        *last += total - base * k;
    }
    counts
}

/// Concurrent ylong throughput: ONE shared `Client` (Arc) with an H1 pool of up
/// to K parallel keep-alive tunnels (`max_h1_conn_number(K)`), driven by K tokio
/// tasks that together perform exactly `cfg.requests` requests. Warmup precedes
/// the measured spawn+join phase. Returns wall-clock seconds of that phase.
async fn bench_ylong_concurrent(cfg: Cfg, proxy_addr: String, origin_url: String) -> f64 {
    let k = cfg.concurrency;
    let client = Arc::new(ylong_client_k(&proxy_addr, k));

    // Warmup, concurrently across K tasks, to prime the K-tunnel pool.
    let warmups = split_work(cfg.warmup, k);
    let mut handles = Vec::with_capacity(k);
    for n in warmups {
        let client = client.clone();
        let url = origin_url.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..n {
                ylong_once(&client, &url).await;
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    // Measured phase.
    let counts = split_work(cfg.requests, k);
    let start = Instant::now();
    let mut handles = Vec::with_capacity(k);
    for n in counts {
        let client = client.clone();
        let url = origin_url.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..n {
                ylong_once(&client, &url).await;
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    start.elapsed().as_secs_f64()
}

/// FAIR concurrent libcurl baseline: K OS threads, each owning its OWN `Easy`
/// handle (never shared) configured identically to `bench_libcurl`, each reusing
/// its handle (keep-alive) for its share of `cfg.requests`. K handles on K
/// threads use K cores with K connections — libcurl's standard concurrency. Warmup
/// is per-thread; the measured phase is the spawn+join wall-clock. Returns seconds,
/// or `None` if any handle fails to configure/perform.
fn bench_libcurl_concurrent(cfg: Cfg, proxy_addr: &str, origin_url: &str) -> Option<f64> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Barrier;

    let k = cfg.concurrency;
    let counts = split_work(cfg.requests, k);
    let warmups = split_work(cfg.warmup, k);
    let failed = Arc::new(AtomicBool::new(false));
    // Barrier so every thread completes warmup (and handle setup) before any
    // starts the timed phase — keeps warmup out of the measured wall-clock while
    // still reusing the same keep-alive handle across warmup + measured requests.
    let barrier = Arc::new(Barrier::new(k));

    let mut threads = Vec::with_capacity(k);
    for i in 0..k {
        let reqs = counts[i];
        let warm = warmups[i];
        let keepalive = cfg.keepalive;
        let proxy_addr = proxy_addr.to_string();
        let origin_url = origin_url.to_string();
        let failed = failed.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || -> f64 {
            // Each thread owns its own Easy handle — never shared across threads.
            let mut h = match libcurl_handle(&origin_url, &proxy_addr, keepalive) {
                Some(h) => h,
                None => {
                    failed.store(true, Ordering::Relaxed);
                    barrier.wait();
                    return 0.0;
                }
            };
            for _ in 0..warm {
                if h.perform().is_err() {
                    failed.store(true, Ordering::Relaxed);
                    barrier.wait();
                    return 0.0;
                }
            }
            // All threads warmed up: start the measured phase together.
            barrier.wait();
            let start = Instant::now();
            for _ in 0..reqs {
                if h.perform().is_err() {
                    failed.store(true, Ordering::Relaxed);
                    return 0.0;
                }
            }
            start.elapsed().as_secs_f64()
        }));
    }
    // Aggregate wall-clock = the slowest thread's measured phase.
    let mut wall = 0.0f64;
    for t in threads {
        wall = wall.max(t.join().unwrap_or(0.0));
    }
    if failed.load(Ordering::Relaxed) {
        return None;
    }
    Some(wall)
}

/// Runs the client-side benchmark against an already-running proxy + origin,
/// printing the same result lines as the all-in-one path. Shared by the
/// all-in-one path and the `BENCH_ROLE=client` path so there is no duplicated
/// client logic. `proxy_addr` is `host:port`; `origin_url` is a full
/// `https://host:port` URL.
async fn run_client(cfg: Cfg, proxy_addr: String, origin_url: String) {
    let reqs = cfg.requests as f64;

    if cfg.concurrency > 1 {
        // CONCURRENT mode: aggregate throughput under K simultaneous workers,
        // ylong (multi-thread async, shared client) vs a FAIR libcurl baseline
        // (K threads, each its own keep-alive Easy handle).
        let k = cfg.concurrency;
        println!("== HTTPS-proxy benchmark (CONCURRENT) ==");
        println!(
            "config: requests={} warmup={} payload={}B keep-alive={} concurrency={}",
            cfg.requests,
            cfg.warmup,
            cfg.payload,
            if cfg.keepalive { "on" } else { "off" },
            k
        );

        let agg_line = |label: &str, secs: f64| {
            println!("{label:<20}{secs:.3}s  ({:.0} req/s agg)", reqs / secs);
        };

        let ylong_secs =
            bench_ylong_concurrent(cfg, proxy_addr.to_string(), origin_url.clone()).await;
        agg_line(&format!("ylong ({k} conc):"), ylong_secs);

        match bench_libcurl_concurrent(cfg, &proxy_addr.to_string(), &origin_url) {
            Some(lib_secs) => {
                agg_line(&format!("libcurl ({k} conc):"), lib_secs);
                // Throughput delta: ylong agg req/s vs libcurl agg req/s.
                let improvement = (lib_secs - ylong_secs) / lib_secs * 100.0;
                println!("ylong vs libcurl (throughput): {improvement:+.1}%");
            }
            None => println!("libcurl ({k} conc): SKIPPED (curl crate / libcurl unavailable)."),
        }

        println!("NOTE: indicative only on this host (parameter sweep via BENCH_* env).");
        return;
    }

    println!("== HTTPS-proxy benchmark ==");
    println!(
        "config: requests={} warmup={} payload={}B keep-alive={}",
        cfg.requests,
        cfg.warmup,
        cfg.payload,
        if cfg.keepalive { "on" } else { "off" }
    );

    let line = |label: &str, secs: f64| {
        println!(
            "{label:<22}{secs:.3}s  ({:.0} req/s, {:.3} ms/req)",
            reqs / secs,
            secs * 1000.0 / reqs
        );
    };

    // BENCH_ONLY=ylong|libcurl runs a single client leg (for isolated profiling,
    // e.g. `perf record`); default runs both + the curl CLI reference.
    let only = std::env::var("BENCH_ONLY").unwrap_or_default();

    let ylong_secs = if only != "libcurl" {
        let s = bench_ylong(cfg, proxy_addr.to_string(), origin_url.clone()).await;
        line("ylong_http_client:", s);
        Some(s)
    } else {
        None
    };

    let lib_secs = if only != "ylong" {
        match bench_libcurl(cfg, &proxy_addr.to_string(), &origin_url) {
            Some(s) => {
                line("libcurl (library):", s);
                Some(s)
            }
            None => {
                println!("libcurl (library): SKIPPED (curl crate / libcurl unavailable).");
                None
            }
        }
    } else {
        None
    };

    if let (Some(y), Some(l)) = (ylong_secs, lib_secs) {
        println!("ylong vs libcurl (throughput): {:+.1}%", (l - y) / l * 100.0);
    }

    // REFERENCE ONLY: the `curl` CLI tool (process/CLI overhead, keep-alive only).
    if only.is_empty() {
        if let Some(cli_secs) = bench_curl(cfg, &proxy_addr.to_string(), &origin_url) {
            line("curl CLI (ref only):", cli_secs);
        }
    }

    println!("NOTE: indicative only on this host (parameter sweep via BENCH_* env).");
}

fn main() {
    let cfg = cfg();
    // Use all available cores so ylong's async runtime can scale across the
    // machine the same way the libcurl baseline (K OS threads) does. Under a
    // `taskset`-pinned process, `available_parallelism` honors the CPU affinity
    // mask, so each role only spins up workers for its allotted cores.
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    // BENCH_RT=current uses a single-thread runtime (I/O driver + task on one
    // thread → readiness handled inline, no cross-thread wake/context-switch per
    // socket-readiness event — the right model for a single connection). Default
    // multi-thread lets ylong scale across cores under concurrency.
    let rt = if std::env::var("BENCH_RT").as_deref() == Ok("current") {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(cores)
            .enable_all()
            .build()
            .unwrap()
    };

    // BENCH_ROLE dispatches between three deployment modes:
    //   server  - run only the fixtures (origin + proxy), print their addresses,
    //             then run forever; never runs a client bench.
    //   client  - run only the client bench against addresses passed via env.
    //   unset/other - the default all-in-one path: fixtures + client in one
    //                  process (unchanged behavior).
    // Splitting server and client lets each be pinned to disjoint CPU cores with
    // `taskset`, eliminating the co-location confound.
    let role = std::env::var("BENCH_ROLE").unwrap_or_default();

    rt.block_on(async {
        match role.as_str() {
            "server" => {
                let acceptor = tls_acceptor();

                let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let origin_addr = origin_listener.local_addr().unwrap();

                let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let proxy_addr = proxy_listener.local_addr().unwrap();

                // Emit the bound addresses so the client process can read them.
                // The client must be launched with the SAME BENCH_PAYLOAD, since
                // the origin server generates the response body from cfg.payload.
                println!("PROXY_ADDR={proxy_addr}");
                println!("ORIGIN_ADDR={origin_addr}");
                std::io::Write::flush(&mut std::io::stdout()).unwrap();

                tokio::spawn(serve_origin(origin_listener, acceptor.clone(), cfg.payload));
                tokio::spawn(serve_proxy(proxy_listener, acceptor.clone()));

                // Keep accepting connections indefinitely; the client process
                // drives the workload and the launcher kills us when done.
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                }
            }
            "client" => {
                // No fixtures here: connect to the server process's listeners.
                let proxy_addr = std::env::var("PROXY_ADDR").expect(
                    "BENCH_ROLE=client requires PROXY_ADDR (host:port of the proxy process)",
                );
                let origin_addr = std::env::var("ORIGIN_ADDR").expect(
                    "BENCH_ROLE=client requires ORIGIN_ADDR (host:port of the origin process)",
                );
                let origin_url = format!("https://{origin_addr}");
                run_client(cfg, proxy_addr, origin_url).await;
            }
            _ => {
                // All-in-one: start fixtures and run the client in this process.
                let acceptor = tls_acceptor();

                let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let origin_addr = origin_listener.local_addr().unwrap();
                tokio::spawn(serve_origin(origin_listener, acceptor.clone(), cfg.payload));

                let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let proxy_addr = proxy_listener.local_addr().unwrap();
                tokio::spawn(serve_proxy(proxy_listener, acceptor.clone()));

                let origin_url = format!("https://{origin_addr}");
                run_client(cfg, proxy_addr.to_string(), origin_url).await;
            }
        }
    });
}
