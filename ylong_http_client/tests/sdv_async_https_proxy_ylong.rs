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

//! SDV test for the HTTPS-proxy (TLS-in-TLS) path on the **`ylong_runtime`**
//! runtime.
//!
//! The companion file `sdv_async_https_proxy.rs` exercises the same feature on
//! the tokio runtime. ylong_http must work on BOTH async runtimes, so this file
//! drives the client through `ylong_runtime::block_on` to prove the proxy TLS
//! handshake, CONNECT tunnel, and nested origin TLS all function there too.
//!
//! Topology: client --TLS--> HTTPS proxy --CONNECT--> origin HTTPS (TLS-in-TLS).
//!
//! The fixture is a single blocking thread that plays BOTH the proxy and the
//! origin: it terminates the proxy TLS, reads the `CONNECT` request, replies
//! `200`, then performs a *nested* TLS accept over that same proxy-TLS stream
//! (acting as the origin) and answers the HTTP request. This avoids needing any
//! async runtime or a bidirectional tunnel pump in the fixture, so the test has
//! no dependency on tokio (which is not built under `ylong_base`).

#![cfg(all(
    feature = "async",
    feature = "http1_1",
    feature = "__tls",
    feature = "ylong_base"
))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream};
use ylong_http::body::async_impl::Body as _;
use ylong_http_client::async_impl::{Body, ClientBuilder, Request};
use ylong_http_client::{Proxy, TlsConfig};

fn file(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/file");
    p.push(name);
    p.to_str().unwrap().to_string()
}

/// Builds a blocking OpenSSL TLS acceptor from the test cert/key fixtures.
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

/// Reads from `stream` until the end of the HTTP head (`\r\n\r\n`). Reads in
/// small chunks; the peer waits for our reply before sending more, so we do not
/// over-read into the next protocol layer.
fn read_head<S: Read>(stream: &mut S) -> std::io::Result<()> {
    let mut acc = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before end of head",
            ));
        }
        acc.extend_from_slice(&buf[..n]);
        if acc.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(());
        }
    }
}

/// Single-connection fixture that is both the TLS proxy and the nested TLS
/// origin. Runs on a blocking thread; returns when the one request is served.
fn serve_proxy_and_origin(listener: TcpListener) {
    let acceptor = tls_acceptor();
    let (tcp, _) = listener.accept().expect("accept failed");

    // 1. Terminate the proxy TLS.
    let mut proxy_tls: SslStream<TcpStream> =
        acceptor.accept(tcp).expect("proxy TLS accept failed");

    // 2. Read the CONNECT request (over the proxy TLS) and accept the tunnel.
    read_head(&mut proxy_tls).expect("reading CONNECT head failed");
    proxy_tls
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .expect("writing 200 failed");
    proxy_tls.flush().ok();

    // 3. Nested TLS: act as the origin server over the same proxy-TLS stream.
    //    This is the inner half of the TLS-in-TLS the client performs.
    let mut origin_tls: SslStream<SslStream<TcpStream>> =
        acceptor.accept(proxy_tls).expect("origin TLS accept failed");

    // 4. Read the tunneled HTTP request and answer it.
    read_head(&mut origin_tls).expect("reading origin request failed");
    origin_tls
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nHi!")
        .expect("writing response failed");
    origin_tls.flush().ok();
    // Give the client time to read before tearing down the TLS session.
    let _ = origin_tls.shutdown();
}

/// SDV test: an HTTPS request succeeds through an HTTPS proxy (TLS-in-TLS),
/// driven entirely on the `ylong_runtime` runtime.
///
/// # Brief
/// 1. Starts a blocking TLS proxy+origin fixture on a worker thread.
/// 2. Builds a ylong client with a proxy-scoped `TlsConfig` and an `https://`
///    proxy URL.
/// 3. Sends an HTTPS request through the proxy on `ylong_runtime`.
/// 4. Verifies the response status and body.
#[test]
fn sdv_async_https_proxy_ylong_success() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || serve_proxy_and_origin(listener));

    ylong_runtime::block_on(async move {
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

        // With a proxy configured the client connects to the proxy and sends
        // `CONNECT`; the origin host need not be resolvable by the client.
        let request = Request::builder()
            .method("GET")
            .url("https://origin.test:443")
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

    server.join().expect("fixture thread panicked");
}
