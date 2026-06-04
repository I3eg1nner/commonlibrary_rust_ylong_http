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

//! Asynchronous HTTPS-proxy example.
//!
//! Demonstrates connecting to an origin server through a TLS-secured ("HTTPS")
//! proxy. The client establishes TLS to the proxy first, issues the `CONNECT`
//! tunnel over the encrypted channel, and then performs the origin TLS
//! handshake nested inside the proxy TLS session (TLS-in-TLS).
//!
//! The proxy-side TLS is configured independently of the origin TLS via
//! `Proxy::...tls_config`. Build the proxy `TlsConfig` to control CA roots
//! (one-way verification), a client certificate (mutual TLS), protocol
//! versions, cipher suites, and SNI.

use ylong_http_client::async_impl::{Body, ClientBuilder, Downloader, Request};
use ylong_http_client::{HttpClientError, Proxy, TlsConfig, TlsVersion};

#[tokio::main]
async fn main() -> Result<(), HttpClientError> {
    // TLS configuration scoped to the proxy connection only. Here we trust a
    // custom CA bundle for the proxy server (one-way verification) and require
    // at least TLS 1.2 for the proxy hop.
    let proxy_tls = TlsConfig::builder()
        .ca_file("./proxy_ca.crt")
        .min_proto_version(TlsVersion::TLS_1_2)
        .build()?;

    // The `https://` scheme tells the client the proxy itself is TLS-secured.
    let client = ClientBuilder::new()
        .proxy(
            Proxy::all("https://proxy.example.com:8443")
                .basic_auth("user", "password")
                .tls_config(proxy_tls)
                .build()?,
        )
        .build()?;

    // The origin request: an HTTPS target reached through the HTTPS proxy.
    let request = Request::builder()
        .url("https://www.example.com")
        .body(Body::empty())?;

    let response = client.request(request).await?;
    let _ = Downloader::console(response).download().await;
    Ok(())
}
