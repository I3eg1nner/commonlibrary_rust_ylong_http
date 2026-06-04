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

// ---- Fixed, documented benchmark configuration -----------------------------
/// Number of measured requests (sequential, keep-alive reused connection).
const REQUESTS: usize = 2_000;
/// Number of warm-up requests excluded from measurement.
const WARMUP: usize = 200;
/// Response payload size in bytes.
const PAYLOAD: usize = 1_024;
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
async fn serve_origin(listener: TcpListener, acceptor: Arc<SslAcceptor>) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
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
                    hyper::service::service_fn(|_req| async {
                        let body = vec![b'a'; PAYLOAD];
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header("Content-Length", PAYLOAD.to_string())
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
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
            }
        });
    }
}

/// Measures `ylong_http_client` over the HTTPS proxy. Returns elapsed seconds
/// for `REQUESTS` measured requests.
async fn bench_ylong(proxy_addr: String, origin_url: String) -> f64 {
    let proxy_tls = TlsConfig::builder()
        .ca_file(file("root-ca.pem"))
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();
    let client = ClientBuilder::new()
        .tls_ca_file(&file("root-ca.pem"))
        .danger_accept_invalid_hostnames(true)
        .proxy(
            Proxy::all(&format!("https://{proxy_addr}"))
                .tls_config(proxy_tls)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    async fn run_once(client: &ylong_http_client::async_impl::Client, url: &str) {
        let req = Request::builder()
            .method("GET")
            .url(url)
            .body(Body::empty())
            .unwrap();
        let mut resp = client.request(req).await.expect("ylong request failed");
        let mut buf = [0u8; 4096];
        while resp.body_mut().data(&mut buf).await.unwrap() != 0 {}
    }

    for _ in 0..WARMUP {
        run_once(&client, &origin_url).await;
    }
    let start = Instant::now();
    for _ in 0..REQUESTS {
        run_once(&client, &origin_url).await;
    }
    start.elapsed().as_secs_f64()
}

/// Measures `libcurl` (via the `curl` binary) over the same HTTPS proxy by
/// reusing a single tunnel for all requests. Returns elapsed seconds, or `None`
/// if curl is unavailable / unsupported.
fn bench_curl(proxy_addr: &str, origin_url: &str) -> Option<f64> {
    // Probe: does this curl support an HTTPS proxy at all?
    let probe = Command::new("curl").arg("--version").output().ok()?;
    if !probe.status.success() {
        return None;
    }

    let mut args: Vec<String> = vec![
        "-s".into(),
        // Match ylong's protocol exactly (HTTP/1.1 to the origin) for a fair
        // comparison; the origin server is HTTP/1.1-only anyway.
        "--http1.1".into(),
        "--proxy".into(),
        format!("https://{proxy_addr}"),
        "--proxy-insecure".into(),
        "--insecure".into(),
    ];
    // Repeat the URL so a single curl process reuses one proxy tunnel,
    // matching ylong's keep-alive behaviour.
    for _ in 0..REQUESTS {
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
    if status.success() {
        Some(elapsed)
    } else {
        None
    }
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let acceptor = tls_acceptor();

        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        tokio::spawn(serve_origin(origin_listener, acceptor.clone()));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(serve_proxy(proxy_listener, acceptor.clone()));

        let origin_url = format!("https://{origin_addr}");

        println!("== HTTPS-proxy benchmark ==");
        println!(
            "config: requests={REQUESTS} warmup={WARMUP} payload={PAYLOAD}B keep-alive=on (sequential)"
        );
        println!("proxy=https://{proxy_addr}  origin={origin_url}");

        let ylong_secs = bench_ylong(proxy_addr.to_string(), origin_url.clone()).await;
        let ylong_rps = REQUESTS as f64 / ylong_secs;
        println!(
            "ylong_http_client: {:.3}s  ({:.0} req/s, {:.3} ms/req)",
            ylong_secs,
            ylong_rps,
            ylong_secs * 1000.0 / REQUESTS as f64
        );

        match bench_curl(&proxy_addr.to_string(), &origin_url) {
            Some(curl_secs) => {
                let curl_rps = REQUESTS as f64 / curl_secs;
                println!(
                    "libcurl:           {:.3}s  ({:.0} req/s, {:.3} ms/req)",
                    curl_secs,
                    curl_rps,
                    curl_secs * 1000.0 / REQUESTS as f64
                );
                let improvement = (curl_secs - ylong_secs) / curl_secs * 100.0;
                println!("ylong vs libcurl (throughput): {improvement:+.1}%");
                println!(
                    "NOTE: indicative only on this host. Re-run on representative hardware to certify the >=20% target."
                );
            }
            None => {
                println!("libcurl: SKIPPED (curl unavailable or HTTPS-proxy unsupported).");
            }
        }
    });
}
