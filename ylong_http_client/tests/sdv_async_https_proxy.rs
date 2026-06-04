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

//! SDV tests for connecting through a TLS-secured ("HTTPS") proxy (TLS-in-TLS).
//!
//! Topology under test:
//!   client --TLS--> HTTPS proxy --CONNECT tunnel--> origin HTTPS server
//!
//! The proxy terminates TLS, reads the `CONNECT` request over the encrypted
//! channel, replies `200`, and then blindly tunnels bytes to the origin. The
//! client performs the origin TLS handshake nested inside the proxy TLS
//! session.

#![cfg(all(
    feature = "async",
    feature = "http1_1",
    feature = "__tls",
    feature = "tokio_base"
))]

use std::path::PathBuf;
use std::sync::Arc;

use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use ylong_http::body::async_impl::Body as _;
use ylong_http_client::async_impl::{Body, ClientBuilder, Request};
use ylong_http_client::{Proxy, TlsConfig};

fn file(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/file");
    p.push(name);
    p.to_str().unwrap().to_string()
}

/// Builds an OpenSSL TLS acceptor from the test cert/key fixtures. Used for
/// both the proxy and the origin server.
fn tls_acceptor() -> SslAcceptor {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor
        .set_private_key_file(file("key.pem"), SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_certificate_chain_file(file("cert.pem"))
        .unwrap();
    acceptor.build()
}

/// Builds a TLS acceptor that requires and verifies a client certificate
/// (mutual TLS), trusting the test root CA.
fn mtls_acceptor() -> SslAcceptor {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor
        .set_private_key_file(file("key.pem"), SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_certificate_chain_file(file("cert.pem"))
        .unwrap();
    // Require the client to present a certificate chaining to the test root CA.
    acceptor.set_ca_file(file("root-ca.pem")).unwrap();
    acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    acceptor.build()
}

/// Origin HTTPS server: terminates TLS and responds `200 Hi!` to one request.
async fn run_origin(listener: TcpListener, acceptor: Arc<SslAcceptor>) {
    let (stream, _) = listener.accept().await.unwrap();
    let ssl = Ssl::new(acceptor.context()).unwrap();
    let mut stream = tokio_openssl::SslStream::new(ssl, stream).unwrap();
    core::pin::Pin::new(&mut stream).accept().await.unwrap();
    hyper::server::conn::Http::new()
        .http1_only(true)
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
        .await
        .ok();
}

/// TLS-secured CONNECT proxy fixture. Terminates TLS, reads the `CONNECT`
/// request, and either replies `407` (when `reply_407`) or `200` followed by a
/// bidirectional byte tunnel to the `CONNECT` target.
///
/// When `head_tx` is provided, the full `CONNECT` request head (read over the
/// proxy TLS session) is sent back so a test can assert on what the proxy
/// received over the encrypted channel.
async fn run_tls_proxy(
    listener: TcpListener,
    acceptor: Arc<SslAcceptor>,
    reply_407: bool,
    head_tx: Option<tokio::sync::oneshot::Sender<String>>,
) {
    let (stream, _) = listener.accept().await.unwrap();
    let ssl = Ssl::new(acceptor.context()).unwrap();
    let mut tls = tokio_openssl::SslStream::new(ssl, stream).unwrap();
    core::pin::Pin::new(&mut tls).accept().await.unwrap();

    // Read the CONNECT request head (over TLS).
    let mut head = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = tls.read(&mut tmp).await.unwrap();
        if n == 0 {
            return;
        }
        head.extend_from_slice(&tmp[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let target = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .expect("CONNECT target")
        .to_string();

    if let Some(tx) = head_tx {
        let _ = tx.send(text);
    }

    if reply_407 {
        tls.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .await
            .unwrap();
        return;
    }

    tls.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .unwrap();

    // Tunnel bytes between the client (over proxy TLS) and the origin.
    let mut upstream = TcpStream::connect(target).await.unwrap();
    tokio::io::copy_bidirectional(&mut tls, &mut upstream)
        .await
        .ok();
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// SDV test: an HTTPS request succeeds through an HTTPS proxy (TLS-in-TLS).
///
/// # Brief
/// 1. Starts a TLS origin server and a TLS-terminating CONNECT proxy.
/// 2. Configures a client with a proxy-scoped `TlsConfig` and an `https://`
///    proxy URL.
/// 3. Sends an HTTPS request to the origin through the proxy.
/// 4. Verifies the response status and body.
#[test]
fn sdv_async_https_proxy_success() {
    let rt = runtime();
    rt.block_on(async {
        let acceptor = Arc::new(tls_acceptor());

        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        tokio::spawn(run_origin(origin_listener, acceptor.clone()));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(run_tls_proxy(proxy_listener, acceptor.clone(), false, None));

        // Proxy-scoped TLS: trust the test root CA, accept the fixture hostname.
        let proxy_tls = TlsConfig::builder()
            .ca_file(file("root-ca.pem"))
            .danger_accept_invalid_hostnames(true)
            .build()
            .unwrap();

        let client = ClientBuilder::new()
            .tls_ca_file(&file("root-ca.pem"))
            .danger_accept_invalid_hostnames(true)
            .proxy(
                Proxy::all(&format!("https://{}", proxy_addr))
                    .tls_config(proxy_tls)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let request = Request::builder()
            .method("GET")
            .url(&format!("https://{}", origin_addr))
            .body(Body::empty())
            .unwrap();

        let mut response = client.request(request).await.expect("request failed");
        assert_eq!(response.status().as_u16(), 200);

        let mut body = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = response.body_mut().data(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            body.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&body, b"Hi!");
    });
}

/// SDV test: a `407` from the HTTPS proxy surfaces as a connection error and
/// the origin TLS handshake is never attempted.
///
/// # Brief
/// 1. Starts a TLS-terminating proxy that replies `407` to `CONNECT`.
/// 2. Configures a client with that HTTPS proxy.
/// 3. Sends an HTTPS request and verifies it fails (no panic, error returned).
#[test]
fn sdv_async_https_proxy_407_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let acceptor = Arc::new(tls_acceptor());

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(run_tls_proxy(proxy_listener, acceptor.clone(), true, None));

        let proxy_tls = TlsConfig::builder()
            .ca_file(file("root-ca.pem"))
            .danger_accept_invalid_hostnames(true)
            .build()
            .unwrap();

        let client = ClientBuilder::new()
            .tls_ca_file(&file("root-ca.pem"))
            .danger_accept_invalid_hostnames(true)
            .proxy(
                Proxy::all(&format!("https://{}", proxy_addr))
                    .tls_config(proxy_tls)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let request = Request::builder()
            .method("GET")
            .url("https://127.0.0.1:1")
            .body(Body::empty())
            .unwrap();

        let result = client.request(request).await;
        assert!(
            result.is_err(),
            "expected a connection error when the proxy returns 407"
        );
    });
}

/// SDV test: an untrusted proxy certificate is rejected for one-way
/// verification.
///
/// # Brief
/// 1. Starts a TLS-terminating proxy presenting the fixture cert.
/// 2. Configures a client whose proxy `TlsConfig` does NOT trust that cert and
///    does not accept invalid certs.
/// 3. Sends a request and verifies the proxy TLS handshake fails.
#[test]
fn sdv_async_https_proxy_untrusted_cert_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let acceptor = Arc::new(tls_acceptor());

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(run_tls_proxy(proxy_listener, acceptor.clone(), false, None));

        // Proxy TLS that does NOT trust the fixture CA and does not accept
        // invalid certs -> the proxy handshake must fail.
        let proxy_tls = TlsConfig::builder()
            .danger_accept_invalid_hostnames(true)
            .build()
            .unwrap();

        let client = ClientBuilder::new()
            .tls_ca_file(&file("root-ca.pem"))
            .danger_accept_invalid_hostnames(true)
            .proxy(
                Proxy::all(&format!("https://{}", proxy_addr))
                    .tls_config(proxy_tls)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let request = Request::builder()
            .method("GET")
            .url("https://127.0.0.1:1")
            .body(Body::empty())
            .unwrap();

        let result = client.request(request).await;
        assert!(
            result.is_err(),
            "expected the proxy TLS handshake to fail for an untrusted proxy cert"
        );
    });
}

/// SDV test: proxy credentials are carried inside the proxy TLS session.
///
/// # Brief
/// 1. Starts a TLS-terminating proxy that captures the `CONNECT` head read over
///    TLS.
/// 2. Configures a client with `basic_auth` on the HTTPS proxy.
/// 3. Sends a request and verifies the proxy received `Proxy-Authorization`
///    over the encrypted channel (it was decoded only after TLS termination).
#[test]
fn sdv_async_https_proxy_auth_in_tls() {
    let rt = runtime();
    rt.block_on(async {
        let acceptor = Arc::new(tls_acceptor());

        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        tokio::spawn(run_origin(origin_listener, acceptor.clone()));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let (head_tx, head_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(run_tls_proxy(
            proxy_listener,
            acceptor.clone(),
            false,
            Some(head_tx),
        ));

        let proxy_tls = TlsConfig::builder()
            .ca_file(file("root-ca.pem"))
            .danger_accept_invalid_hostnames(true)
            .build()
            .unwrap();

        let client = ClientBuilder::new()
            .tls_ca_file(&file("root-ca.pem"))
            .danger_accept_invalid_hostnames(true)
            .proxy(
                Proxy::all(&format!("https://{}", proxy_addr))
                    .basic_auth("Aladdin", "open sesame")
                    .tls_config(proxy_tls)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let request = Request::builder()
            .method("GET")
            .url(&format!("https://{}", origin_addr))
            .body(Body::empty())
            .unwrap();

        let response = client.request(request).await.expect("request failed");
        assert_eq!(response.status().as_u16(), 200);

        // The proxy received the credentials only after terminating TLS, proving
        // they were transmitted inside the proxy TLS session.
        let head = head_rx
            .await
            .expect("proxy did not report the CONNECT head");
        assert!(
            head.contains("Proxy-Authorization: Basic "),
            "CONNECT head should carry Proxy-Authorization; got:\n{head}"
        );
    });
}

/// SDV test: mutual TLS (two-way verification) to the proxy succeeds when the
/// client presents a valid certificate and private key.
///
/// # Brief
/// 1. Starts a TLS origin and a proxy that requires a client certificate.
/// 2. Configures the client's proxy `TlsConfig` with a client cert + private
///    key.
/// 3. Sends an HTTPS request and verifies it succeeds.
#[test]
fn sdv_async_https_proxy_mtls_success() {
    let rt = runtime();
    rt.block_on(async {
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        tokio::spawn(run_origin(origin_listener, Arc::new(tls_acceptor())));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(run_tls_proxy(
            proxy_listener,
            Arc::new(mtls_acceptor()),
            false,
            None,
        ));

        // Present a client certificate + private key for mutual TLS to the proxy.
        let proxy_tls = TlsConfig::builder()
            .ca_file(file("root-ca.pem"))
            .danger_accept_invalid_hostnames(true)
            .certificate_file(file("cert.pem"), ylong_http_client::TlsFileType::PEM)
            .private_key_file(file("key.pem"), ylong_http_client::TlsFileType::PEM)
            .build()
            .unwrap();

        let client = ClientBuilder::new()
            .tls_ca_file(&file("root-ca.pem"))
            .danger_accept_invalid_hostnames(true)
            .proxy(
                Proxy::all(&format!("https://{}", proxy_addr))
                    .tls_config(proxy_tls)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let request = Request::builder()
            .method("GET")
            .url(&format!("https://{}", origin_addr))
            .body(Body::empty())
            .unwrap();

        let mut response = client.request(request).await.expect("mTLS request failed");
        assert_eq!(response.status().as_u16(), 200);

        let mut body = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = response.body_mut().data(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            body.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&body, b"Hi!");
    });
}

/// SDV test: a proxy requiring mutual TLS rejects a client that presents no
/// certificate, and the failure surfaces clearly.
///
/// # Brief
/// 1. Starts a proxy that requires a client certificate.
/// 2. Configures the client's proxy `TlsConfig` WITHOUT a client certificate.
/// 3. Sends an HTTPS request and verifies it fails.
#[test]
fn sdv_async_https_proxy_mtls_missing_cert_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(run_tls_proxy(
            proxy_listener,
            Arc::new(mtls_acceptor()),
            false,
            None,
        ));

        // No client certificate configured -> the proxy must reject the handshake.
        let proxy_tls = TlsConfig::builder()
            .ca_file(file("root-ca.pem"))
            .danger_accept_invalid_hostnames(true)
            .build()
            .unwrap();

        let client = ClientBuilder::new()
            .tls_ca_file(&file("root-ca.pem"))
            .danger_accept_invalid_hostnames(true)
            .proxy(
                Proxy::all(&format!("https://{}", proxy_addr))
                    .tls_config(proxy_tls)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let request = Request::builder()
            .method("GET")
            .url("https://127.0.0.1:1")
            .body(Body::empty())
            .unwrap();

        let result = client.request(request).await;
        assert!(
            result.is_err(),
            "expected mutual-TLS proxy to reject a client with no certificate"
        );
    });
}
