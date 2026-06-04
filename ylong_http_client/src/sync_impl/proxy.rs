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

//! Synchronous proxy module.
//!
//! Mirrors [`crate::async_impl::proxy`] for the synchronous client: it
//! decouples proxy tunnel establishment from the connector behind the
//! [`TunnelConnect`] abstraction so that new proxy protocols can be added
//! without changing the connector.

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::util::c_openssl::adapter::TlsConfig;
use crate::util::c_openssl::ssl::SslStream;
use crate::{ErrorKind, HttpClientError};

/// The transport that carries the origin connection through a proxy. See
/// [`crate::async_impl::proxy::ProxyTunnel`] for details; this is the
/// synchronous counterpart.
#[derive(Debug)]
pub enum ProxyTunnel {
    /// Plain TCP transport (direct connection or plaintext proxy tunnel).
    Plain(TcpStream),
    /// TLS session to the proxy server (HTTPS proxy).
    Tls(Box<SslStream<TcpStream>>),
}

impl Read for ProxyTunnel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ProxyTunnel::Plain(s) => s.read(buf),
            ProxyTunnel::Tls(s) => s.read(buf),
        }
    }
}

impl Write for ProxyTunnel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ProxyTunnel::Plain(s) => s.write(buf),
            ProxyTunnel::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ProxyTunnel::Plain(s) => s.flush(),
            ProxyTunnel::Tls(s) => s.flush(),
        }
    }
}

/// Establishes a proxy tunnel over a freshly connected TCP stream, returning
/// the [`ProxyTunnel`] transport on which the origin connection will be
/// layered.
///
/// Implement this trait to add support for a new proxy protocol without
/// touching the connector.
pub(crate) trait TunnelConnect {
    fn tunnel(
        self,
        tcp: TcpStream,
        host: &str,
        port: u16,
        auth: Option<String>,
    ) -> Result<ProxyTunnel, HttpClientError>;
}

/// A plaintext (HTTP) proxy: issues the `CONNECT` tunnel directly over TCP.
pub(crate) struct HttpProxyTunnel;

impl TunnelConnect for HttpProxyTunnel {
    fn tunnel(
        self,
        tcp: TcpStream,
        host: &str,
        port: u16,
        auth: Option<String>,
    ) -> Result<ProxyTunnel, HttpClientError> {
        let tcp = connect_tunnel(tcp, host, port, auth)?;
        Ok(ProxyTunnel::Plain(tcp))
    }
}

/// A TLS-secured (HTTPS) proxy: establishes TLS to the proxy first, then issues
/// the `CONNECT` tunnel over the encrypted channel.
pub(crate) struct HttpsProxyTunnel {
    pub(crate) config: TlsConfig,
    pub(crate) proxy_host: String,
}

impl TunnelConnect for HttpsProxyTunnel {
    fn tunnel(
        self,
        tcp: TcpStream,
        host: &str,
        port: u16,
        auth: Option<String>,
    ) -> Result<ProxyTunnel, HttpClientError> {
        // 1. Establish TLS to the proxy server before sending anything.
        let proxy_tls = self
            .config
            .ssl_new(&self.proxy_host)
            .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?
            .into_inner()
            .connect(tcp)
            .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;

        // 2. Issue the CONNECT tunnel over the proxy TLS session.
        let proxy_tls = connect_tunnel(proxy_tls, host, port, auth)?;
        Ok(ProxyTunnel::Tls(Box::new(proxy_tls)))
    }
}

/// Sends a `CONNECT host:port` request over `conn` and validates the proxy
/// response. Works over either a plain `TcpStream` or a TLS stream to the
/// proxy.
pub(crate) fn connect_tunnel<S>(
    mut conn: S,
    host: &str,
    port: u16,
    auth: Option<String>,
) -> Result<S, HttpClientError>
where
    S: Read + Write,
{
    let mut req = Vec::new();

    // `unwrap()` never fails here (writing into a `Vec`).
    write!(
        &mut req,
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    )
    .unwrap();

    if let Some(value) = auth {
        write!(&mut req, "Proxy-Authorization: Basic {value}\r\n").unwrap();
    }

    write!(&mut req, "\r\n").unwrap();

    conn.write_all(&req)
        .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;

    let mut buf = [0; 8192];
    let mut pos = 0;

    loop {
        let n = conn
            .read(&mut buf[pos..])
            .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;

        if n == 0 {
            return Err(HttpClientError::from_str(
                ErrorKind::Connect,
                "Error receiving from proxy",
            ));
        }

        pos += n;
        let resp = &buf[..pos];
        if resp.starts_with(b"HTTP/1.1 200") || resp.starts_with(b"HTTP/1.0 200") {
            if resp.ends_with(b"\r\n\r\n") {
                return Ok(conn);
            }
            if pos == buf.len() {
                return Err(HttpClientError::from_str(
                    ErrorKind::Connect,
                    "proxy headers too long for tunnel",
                ));
            }
        } else if resp.starts_with(b"HTTP/1.1 407") {
            return Err(HttpClientError::from_str(
                ErrorKind::Connect,
                "proxy authentication required",
            ));
        } else {
            return Err(HttpClientError::from_str(
                ErrorKind::Connect,
                "unsuccessful tunnel",
            ));
        }
    }
}
