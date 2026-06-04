// Copyright (c) 2023 Huawei Device Co., Ltd.
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

use std::error::Error;
use std::io::{Read, Write};
use std::mem::take;
use std::sync::{Arc, Mutex};

use ylong_http::request::uri::Uri;

use crate::error::{ErrorKind, HttpClientError};
use crate::sync_impl::Connector;
use crate::util::dispatcher::{Conn, ConnDispatcher, Dispatcher};
use crate::util::pool::{Pool, PoolKey};
use crate::util::progress::SpeedConfig;

/// Maximum number of pooled connections per host for the synchronous client.
/// The synchronous `Conns` does not bound concurrency, so this is only the
/// value threaded through `Pool::get`'s `create_fn`.
const SYNC_MAX_CONN_NUM: usize = 6;

pub(crate) struct ConnPool<C, S> {
    pool: Pool<PoolKey, Conns<S>>,
    connector: Arc<C>,
}

impl<C: Connector> ConnPool<C, C::Stream> {
    pub(crate) fn new(connector: C) -> Self {
        Self {
            pool: Pool::new(),
            connector: Arc::new(connector),
        }
    }

    pub(crate) fn connect_to(&self, uri: Uri) -> Result<Conn<C::Stream>, HttpClientError> {
        let key = PoolKey::new(
            uri.scheme().unwrap().clone(),
            uri.authority().unwrap().clone(),
        );

        self.pool
            .get(key, Conns::new, SYNC_MAX_CONN_NUM, SpeedConfig::none())
            .conn(|| self.connector.clone().connect(&uri))
    }
}

pub(crate) struct Conns<S> {
    list: Arc<Mutex<Vec<ConnDispatcher<S>>>>,
}

impl<S> Conns<S> {
    /// Signature matches `Pool::get`'s `create_fn`. The synchronous pool does
    /// not use the connection-count or speed parameters, so they are
    /// ignored.
    fn new(_max_conn_num: usize, _speed_config: SpeedConfig) -> Self {
        Self {
            list: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl<S> Clone for Conns<S> {
    fn clone(&self) -> Self {
        Self {
            list: self.list.clone(),
        }
    }
}

impl<S: Read + Write + 'static> Conns<S> {
    fn conn<F, E>(&self, connect_fn: F) -> Result<Conn<S>, HttpClientError>
    where
        F: FnOnce() -> Result<S, E>,
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        let mut list = self.list.lock().unwrap();
        let mut conn = None;
        let curr = take(&mut *list);
        for dispatcher in curr.into_iter() {
            // Discard invalid dispatchers.
            if dispatcher.is_shutdown() {
                continue;
            }
            if conn.is_none() {
                conn = dispatcher.dispatch();
            }
            list.push(dispatcher);
        }

        if let Some(conn) = conn {
            Ok(conn)
        } else {
            let dispatcher = ConnDispatcher::http1(
                connect_fn().map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?,
            );
            // We must be able to get the `Conn` here.
            let conn = dispatcher.dispatch().unwrap();
            list.push(dispatcher);
            Ok(conn)
        }
    }
}
