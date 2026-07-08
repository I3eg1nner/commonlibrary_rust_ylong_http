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

//! Criterion micro-benchmark for the HTTPS-proxy (TLS-in-TLS) request path.
//!
//! This is the `criterion`-framework companion to the custom, comparison-focused
//! `https_proxy_bench.rs`. Criterion gives statistically rigorous per-request
//! latency estimates (with outlier detection and confidence intervals) for the
//! steady-state, keep-alive HTTPS-proxy GET, which is exactly the single-request
//! latency the project reports as at-parity with libcurl.
//!
//! Topology: client --TLS--> HTTPS proxy --CONNECT--> origin HTTPS (TLS-in-TLS),
//! all in-process. Run with:
//!   OPENSSL_DIR=<prefix> LD_LIBRARY_PATH=<prefix>/lib \
//!   RUSTFLAGS="-L <prefix>/lib -l ssl -l crypto" \
//!   cargo bench --no-default-features \
//!     --features async,http1_1,tokio_base,tls_default \
//!     --bench https_proxy_criterion

#![cfg(all(
    feature = "async",
    feature = "http1_1",
    feature = "__tls",
    feature = "tokio_base"
))]

use std::path::PathBuf;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};
use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use ylong_http::body::async_impl::Body as _;
use ylong_http_client::async_impl::{Body, Client, ClientBuilder, Request};
use ylong_http_client::{Proxy, TlsConfig};

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

/// Origin HTTPS server: keep-alive, fixed `payload`-byte body.
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
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header("Content-Length", payload.to_string())
                                .body(hyper::Body::from(vec![b'a'; payload]))
                                .unwrap(),
                        )
                    }),
                )
                .await;
        });
    }
}

/// TLS-terminating CONNECT proxy: tunnels each connection to its CONNECT target.
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
            let target = match text.lines().next().and_then(|l| l.split_whitespace().nth(1)) {
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

/// Builds a ylong client that reaches the origin through the HTTPS proxy, with
/// the proxy cert verified against the test root CA (same as the SDV tests).
fn ylong_client(proxy_addr: &str) -> Client {
    let proxy_tls = TlsConfig::builder()
        .ca_file(file("root-ca.pem"))
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();
    ClientBuilder::new()
        .tls_ca_file(&file("root-ca.pem"))
        .danger_accept_invalid_hostnames(true)
        .max_h1_conn_number(1)
        .proxy(
            Proxy::all(&format!("https://{proxy_addr}"))
                .tls_config(proxy_tls)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

async fn ylong_once(client: &Client, url: &str) {
    let req = Request::builder()
        .method("GET")
        .url(url)
        .body(Body::empty())
        .unwrap();
    let mut resp = client.request(req).await.expect("ylong request failed");
    let mut buf = [0u8; 16384];
    while resp.body_mut().data(&mut buf).await.unwrap() != 0 {}
}

fn bench_https_proxy(c: &mut Criterion) {
    // One shared multi-thread runtime hosts both the in-process fixtures and the
    // client, so the measured future is a full keep-alive GET through the proxy.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();

    let payload: usize = std::env::var("BENCH_PAYLOAD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024);

    let (client, origin_url) = rt.block_on(async {
        let acceptor = tls_acceptor();

        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        tokio::spawn(serve_origin(origin_listener, acceptor.clone(), payload));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(serve_proxy(proxy_listener, acceptor.clone()));

        let client = Arc::new(ylong_client(&proxy_addr.to_string()));
        let origin_url = format!("https://{origin_addr}");
        // Prime the keep-alive tunnel so the measured samples are steady-state.
        ylong_once(&client, &origin_url).await;
        (client, origin_url)
    });

    let mut group = c.benchmark_group("https_proxy_tls_in_tls");
    group.bench_function(format!("get_keepalive_{payload}B"), |b| {
        b.to_async(&rt).iter(|| {
            let client = client.clone();
            let url = origin_url.clone();
            async move { ylong_once(&client, &url).await }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_https_proxy);
criterion_main!(benches);
