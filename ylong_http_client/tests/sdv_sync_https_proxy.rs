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

//! SDV tests for the synchronous client through a TLS-secured ("HTTPS") proxy
//! (TLS-in-TLS).
//!
//! The proxy + origin servers run on a background tokio runtime; the blocking
//! synchronous client drives the request on the test thread.

#![cfg(all(
    feature = "sync",
    feature = "http1_1",
    feature = "__tls",
    feature = "tokio_base"
))]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use ylong_http::body::TextBody;
use ylong_http::request::RequestBuilder;
use ylong_http_client::sync_impl::Body as _;
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
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header("Content-Length", "3")
                                .body(hyper::Body::from("Hi!"))
                                .unwrap(),
                        )
                    }),
                )
                .await;
        });
    }
}

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

/// Spawns the TLS proxy + TLS origin on a background tokio runtime and returns
/// their addresses. The runtime is kept alive for the duration of the test.
fn spawn_servers() -> (SocketAddr, SocketAddr) {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let acceptor = tls_acceptor();
            let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_addr = origin_listener.local_addr().unwrap();
            tokio::spawn(serve_origin(origin_listener, acceptor.clone()));

            let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_addr = proxy_listener.local_addr().unwrap();
            tokio::spawn(serve_proxy(proxy_listener, acceptor.clone()));

            tx.send((proxy_addr, origin_addr)).unwrap();
            // Keep the runtime (and thus the servers) alive for the test.
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
    });
    rx.recv().expect("servers failed to start")
}

/// SDV test: a synchronous HTTPS request succeeds through an HTTPS proxy.
///
/// # Brief
/// 1. Starts a TLS origin server and a TLS-terminating CONNECT proxy
///    (background runtime).
/// 2. Builds a synchronous client with a proxy-scoped `TlsConfig` and an `https://`
///    proxy URL.
/// 3. Sends an HTTPS request to the origin through the proxy.
/// 4. Verifies the response status and body.
#[test]
fn sdv_sync_https_proxy_success() {
    let (proxy_addr, origin_addr) = spawn_servers();

    let proxy_tls = TlsConfig::builder()
        .ca_file(file("root-ca.pem"))
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();

    let client = ylong_http_client::sync_impl::Client::builder()
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

    let request = RequestBuilder::new()
        .method("GET")
        .url(format!("https://{origin_addr}").as_str())
        .body(TextBody::from_bytes(b""))
        .unwrap();

    let mut response = client.request(request).expect("sync request failed");
    assert_eq!(response.status().as_u16(), 200);

    let mut buf = [0u8; 4096];
    let mut size = 0;
    loop {
        let read = response
            .body_mut()
            .data(&mut buf[size..])
            .expect("body read failed");
        if read == 0 {
            break;
        }
        size += read;
    }
    assert_eq!(&buf[..size], b"Hi!");
}
