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

//! Asynchronous proxy module.
//!
//! This module decouples proxy tunnel establishment from the HTTP connector.
//! The connector selects a proxy (see [`crate::util::proxy`]) and then
//! delegates tunnel establishment to an implementation of [`TunnelConnect`].
//! Adding a new proxy protocol means adding a new [`TunnelConnect`]
//! implementation; the connector itself does not need to change.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::error;
use std::fmt::{Debug, Display, Formatter};
use std::io::{Error, ErrorKind, Write};

use crate::async_impl::ssl_stream::AsyncSslStream;
use crate::runtime::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, TcpStream};
use crate::util::c_openssl::adapter::TlsConfig;
use crate::{ErrorKind as ClientErrorKind, HttpClientError};

/// The transport that carries the origin connection through a proxy.
///
/// For a plaintext (HTTP) proxy this is the raw [`TcpStream`] returned after
/// the `CONNECT` tunnel is accepted. For a TLS-secured (HTTPS) proxy this is
/// the TLS session established to the proxy, over which the `CONNECT` tunnel
/// and then the origin TLS handshake (TLS-in-TLS) are performed.
///
/// `ProxyTunnel` implements [`AsyncRead`]/[`AsyncWrite`], so the origin TLS
/// layer can wrap it uniformly regardless of whether the proxy hop itself is
/// encrypted.
pub enum ProxyTunnel {
    /// Plain TCP transport (direct connection or plaintext proxy tunnel).
    Plain(TcpStream),
    /// TLS session to the proxy server (HTTPS proxy).
    Tls(Box<AsyncSslStream<TcpStream>>),
}

impl AsyncRead for ProxyTunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ProxyTunnel::Plain(s) => Pin::new(s).poll_read(cx, buf),
            ProxyTunnel::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ProxyTunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ProxyTunnel::Plain(s) => Pin::new(s).poll_write(cx, buf),
            ProxyTunnel::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ProxyTunnel::Plain(s) => Pin::new(s).poll_flush(cx),
            ProxyTunnel::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ProxyTunnel::Plain(s) => Pin::new(s).poll_shutdown(cx),
            ProxyTunnel::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Establishes a proxy tunnel to a target `host:port` over a freshly connected
/// TCP stream, returning the [`ProxyTunnel`] transport on which the origin
/// connection will be layered.
///
/// Implement this trait to add support for a new proxy protocol without
/// touching the connector.
pub(crate) trait TunnelConnect {
    /// Consumes the raw TCP stream to the proxy and returns the tunnel
    /// transport to the origin `host:port`.
    fn tunnel(
        &self,
        tcp: TcpStream,
        host: &str,
        port: u16,
        auth: Option<String>,
    ) -> impl core::future::Future<Output = Result<ProxyTunnel, HttpClientError>> + Send;
}

/// A plaintext (HTTP) proxy: issues the `CONNECT` tunnel directly over TCP.
pub(crate) struct HttpProxyTunnel;

impl TunnelConnect for HttpProxyTunnel {
    async fn tunnel(
        &self,
        tcp: TcpStream,
        host: &str,
        port: u16,
        auth: Option<String>,
    ) -> Result<ProxyTunnel, HttpClientError> {
        let tcp = connect_tunnel(tcp, host, port, auth)
            .await
            .map_err(|e| HttpClientError::from_io_error(ClientErrorKind::Connect, e))?;
        Ok(ProxyTunnel::Plain(tcp))
    }
}

/// A TLS-secured (HTTPS) proxy: establishes TLS to the proxy first, then issues
/// the `CONNECT` tunnel over the encrypted channel so that the request line and
/// any `Proxy-Authorization` credentials are never sent in plaintext.
pub(crate) struct HttpsProxyTunnel {
    /// TLS configuration scoped to the proxy connection.
    pub(crate) config: TlsConfig,
    /// Host name used for the proxy TLS handshake (SNI / hostname
    /// verification).
    pub(crate) proxy_host: String,
}

impl TunnelConnect for HttpsProxyTunnel {
    async fn tunnel(
        &self,
        tcp: TcpStream,
        host: &str,
        port: u16,
        auth: Option<String>,
    ) -> Result<ProxyTunnel, HttpClientError> {
        // 1. Establish TLS to the proxy server before sending anything.
        let pinned_key = self.config.pinning_host_match(self.proxy_host.as_str());
        let mut proxy_tls = self
            .config
            .ssl_new(&self.proxy_host)
            .and_then(|ssl| AsyncSslStream::new(ssl.into_inner(), tcp, pinned_key))
            .map_err(|e| {
                HttpClientError::from_tls_error(
                    ClientErrorKind::Connect,
                    Error::new(ErrorKind::Other, e),
                )
            })?;
        Pin::new(&mut proxy_tls).connect().await.map_err(|e| {
            HttpClientError::from_tls_error(
                ClientErrorKind::Connect,
                Error::new(ErrorKind::Other, e),
            )
        })?;

        // 2. Issue the CONNECT tunnel over the proxy TLS session.
        let proxy_tls = connect_tunnel(proxy_tls, host, port, auth)
            .await
            .map_err(|e| HttpClientError::from_io_error(ClientErrorKind::Connect, e))?;

        Ok(ProxyTunnel::Tls(Box::new(proxy_tls)))
    }
}

/// Sends a `CONNECT host:port` request over `conn` and validates the proxy
/// response. On success the same `conn` (now a tunnel to the origin) is
/// returned.
///
/// `conn` may be a plain `TcpStream` (HTTP proxy) or a TLS stream to the proxy
/// (HTTPS proxy); the logic is identical because both implement async I/O.
pub(crate) async fn connect_tunnel<S>(
    mut conn: S,
    host: &str,
    port: u16,
    auth: Option<String>,
) -> Result<S, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = Vec::new();

    write!(
        &mut req,
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    )?;

    if let Some(value) = auth {
        write!(&mut req, "Proxy-Authorization: Basic {value}\r\n")?;
    }

    write!(&mut req, "\r\n")?;

    conn.write_all(&req).await?;

    let mut buf = [0; 8192];
    let mut pos = 0;

    loop {
        let n = conn.read(&mut buf[pos..]).await?;

        if n == 0 {
            return Err(other_io_error(CreateTunnelErr::Unsuccessful));
        }

        pos += n;
        let resp = &buf[..pos];
        if resp.starts_with(b"HTTP/1.1 200") || resp.starts_with(b"HTTP/1.0 200") {
            if resp.ends_with(b"\r\n\r\n") {
                return Ok(conn);
            }
            if pos == buf.len() {
                return Err(other_io_error(CreateTunnelErr::ProxyHeadersTooLong));
            }
        } else if resp.starts_with(b"HTTP/1.1 407") {
            return Err(other_io_error(CreateTunnelErr::ProxyAuthenticationRequired));
        } else {
            return Err(other_io_error(CreateTunnelErr::Unsuccessful));
        }
    }
}

pub(crate) fn other_io_error(err: CreateTunnelErr) -> Error {
    Error::new(ErrorKind::Other, err)
}

pub(crate) enum CreateTunnelErr {
    ProxyHeadersTooLong,
    ProxyAuthenticationRequired,
    Unsuccessful,
}

impl Debug for CreateTunnelErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProxyHeadersTooLong => f.write_str("Proxy headers too long for tunnel"),
            Self::ProxyAuthenticationRequired => f.write_str("Proxy authentication required"),
            Self::Unsuccessful => f.write_str("Unsuccessful tunnel"),
        }
    }
}

impl Display for CreateTunnelErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl error::Error for CreateTunnelErr {}

#[cfg(all(test, feature = "__tls", feature = "ylong_base"))]
mod ut_proxy {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use ylong_runtime::io::AsyncWriteExt;

    use crate::async_impl::connector::tcp_stream;
    use crate::async_impl::dns::{EyeBallConfig, HappyEyeballs};
    use crate::async_impl::proxy::{connect_tunnel, other_io_error, CreateTunnelErr};
    use crate::start_tcp_server;
    use crate::util::test_utils::{format_header_str, TcpHandle};

    /// UT test cases for `connect_tunnel`.
    ///
    /// # Brief
    /// 1. Creates a `tcp stream` by calling `tcp_stream`.
    /// 2. Sends a `CONNECT` request by `connect_tunnel`.
    /// 3. Checks if the result is as expected.
    #[test]
    fn ut_ssl_tunnel_error() {
        let mut handles = vec![];
        start_tcp_server!(
           Handles: handles,
           EndWith: "\r\n\r\n",
           Shutdown: std::net::Shutdown::Both,
        );
        let handle = handles.pop().expect("No more handles !");

        let eyeballs = HappyEyeballs::new(
            vec![SocketAddr::from_str(handle.addr.as_str()).unwrap()],
            EyeBallConfig::new(None, None),
        );

        let handle = ylong_runtime::spawn(async move {
            let tcp = tcp_stream(eyeballs).await.unwrap();
            let res = connect_tunnel(
                tcp,
                "ylong_http.com",
                443,
                Some(String::from("base64 bytes")),
            )
            .await;
            assert_eq!(
                format!("{:?}", res.err()),
                format!("{:?}", Some(other_io_error(CreateTunnelErr::Unsuccessful)))
            );
            handle
                .server_shutdown
                .recv()
                .expect("server send order failed !");
        });
        ylong_runtime::block_on(handle).unwrap();

        start_tcp_server!(
           Handles: handles,
           EndWith: "\r\n\r\n",
           Response: {
               Status: 407,
               Version: "HTTP/1.1",
               Header: "Content-Length", "11",
               Body: "METHOD GET!",
           },
           Shutdown: std::net::Shutdown::Both,
        );
        let handle = handles.pop().expect("No more handles !");

        let eyeballs = HappyEyeballs::new(
            vec![SocketAddr::from_str(handle.addr.as_str()).unwrap()],
            EyeBallConfig::new(None, None),
        );
        let handle = ylong_runtime::spawn(async move {
            let tcp = tcp_stream(eyeballs).await.unwrap();
            let res = connect_tunnel(
                tcp,
                "ylong_http.com",
                443,
                Some(String::from("base64 bytes")),
            )
            .await;
            assert_eq!(
                format!("{:?}", res.err()),
                format!(
                    "{:?}",
                    Some(other_io_error(CreateTunnelErr::ProxyAuthenticationRequired))
                )
            );
            handle
                .server_shutdown
                .recv()
                .expect("server send order failed !");
        });
        ylong_runtime::block_on(handle).unwrap();
    }

    /// UT test cases for `connect_tunnel`.
    ///
    /// # Brief
    /// 1. Creates a `tcp stream` by calling `tcp_stream`.
    /// 2. Sends a `CONNECT` request by `connect_tunnel`.
    /// 3. Checks if the result is as expected.
    #[test]
    fn ut_ssl_tunnel_connect() {
        let mut handles = vec![];

        start_tcp_server!(
           Handles: handles,
           EndWith: "\r\n\r\n",
            Response: {
               Status: 200,
               Version: "HTTP/1.1",
               Body: "",
           },
           Shutdown: std::net::Shutdown::Both,
        );
        let handle = handles.pop().expect("No more handles !");

        let eyeballs = HappyEyeballs::new(
            vec![SocketAddr::from_str(handle.addr.as_str()).unwrap()],
            EyeBallConfig::new(None, None),
        );
        let handle = ylong_runtime::spawn(async move {
            let tcp = tcp_stream(eyeballs).await.unwrap();
            let res = connect_tunnel(
                tcp,
                "ylong_http.com",
                443,
                Some(String::from("base64 bytes")),
            )
            .await;
            assert!(res.is_ok());
            handle
                .server_shutdown
                .recv()
                .expect("server send order failed !");
        });
        ylong_runtime::block_on(handle).unwrap();
    }

    /// UT test cases for response beyond size of `connect_tunnel`.
    ///
    /// # Brief
    /// 1. Creates a `tcp stream` by calling `tcp_stream`.
    /// 2. Sends a `CONNECT` request by `connect_tunnel`.
    /// 3. Checks if the result is as expected.
    #[test]
    fn ut_ssl_tunnel_resp_beyond_size() {
        let mut handles = vec![];

        let buf = vec![b'b'; 8192];
        let body = String::from_utf8(buf).unwrap();

        start_tcp_server!(
           Handles: handles,
           EndWith: "\r\n\r\n",
            Response: {
               Status: 200,
               Version: "HTTP/1.1",
               Header: "Content-Length", "11",
               Body: body.as_str(),
           },
        );
        let handle = handles.pop().expect("No more handles !");

        let eyeballs = HappyEyeballs::new(
            vec![SocketAddr::from_str(handle.addr.as_str()).unwrap()],
            EyeBallConfig::new(None, None),
        );
        let handle = ylong_runtime::spawn(async move {
            let tcp = tcp_stream(eyeballs).await.unwrap();
            let res = connect_tunnel(
                tcp,
                "ylong_http.com",
                443,
                Some(String::from("base64 bytes")),
            )
            .await;
            assert_eq!(
                format!("{:?}", res.err()),
                format!(
                    "{:?}",
                    Some(other_io_error(CreateTunnelErr::ProxyHeadersTooLong))
                )
            );
            handle
                .server_shutdown
                .recv()
                .expect("server send order failed !");
        });
        ylong_runtime::block_on(handle).unwrap();
    }

    /// UT test cases for debug of `CreateTunnelErr`.
    ///
    /// # Brief
    /// 1. Checks `CreateTunnelErr` debug by calling `CreateTunnelErr::fmt`.
    /// 2. Checks if the result is as expected.
    #[test]
    fn ut_tunnel_error_debug_assert() {
        assert_eq!(
            format!("{:?}", CreateTunnelErr::ProxyHeadersTooLong),
            "Proxy headers too long for tunnel"
        );
        assert_eq!(
            format!("{:?}", CreateTunnelErr::ProxyAuthenticationRequired),
            "Proxy authentication required"
        );
        assert_eq!(
            format!("{:?}", CreateTunnelErr::Unsuccessful),
            "Unsuccessful tunnel"
        );
        assert_eq!(
            format!("{}", CreateTunnelErr::ProxyHeadersTooLong),
            "Proxy headers too long for tunnel"
        );
    }
}
