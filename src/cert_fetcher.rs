// Copyright Istio Authors
//
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

use crate::config;
use crate::config::ProxyMode;
use crate::identity::Priority::Warmup;
use crate::identity::{Identity, SecretManager};
use crate::state::workload::{Protocol, Workload};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Responsible for pre-fetching certs for workloads.
/// 负责为workloads预取certs
pub trait CertFetcher: Send + Sync {
    fn prefetch_cert(&self, w: &Workload);
}

/// A no-op implementation of [CertFetcher].
pub struct NoCertFetcher();

impl CertFetcher for NoCertFetcher {
    fn prefetch_cert(&self, _: &Workload) {}
}

/// Constructs an appropriate [CertFetcher] for the proxy config.
/// 构建一个合适的[CertFetcher]，对于proxy config
pub fn new(cfg: &config::Config, cert_manager: Arc<SecretManager>) -> Arc<dyn CertFetcher> {
    match cfg.proxy_mode {
        ProxyMode::Dedicated => Arc::new(NoCertFetcher()),
        ProxyMode::Shared => Arc::new(CertFetcherImpl::new(cfg, cert_manager)),
    }
}

/// A real [CertFetcher] that asynchronously forwards cert pre-fetch requests to a [SecretManager].
struct CertFetcherImpl {
    proxy_mode: ProxyMode,
    local_node: Option<String>,
    tx: mpsc::Sender<Identity>,
}

impl CertFetcherImpl {
    fn new(cfg: &config::Config, cert_manager: Arc<SecretManager>) -> Self {
        let (tx, mut rx) = mpsc::channel::<Identity>(256);

        // Spawn a task for handling the pre-fetch requests asynchronously.
        // 生成一个task用于异步处理pre-fetch requests
        tokio::spawn(async move {
            while let Some(workload_identity) = rx.recv().await {
                match cert_manager
                    // 拉取cert
                    .fetch_certificate_pri(&workload_identity, Warmup)
                    .await
                {
                    // 为workload拉取cert
                    Ok(_) => debug!("prefetched cert for {:?}", workload_identity.to_string()),
                    Err(e) => error!(
                        "unable to prefetch cert for {:?}, skipping, {:?}",
                        workload_identity.to_string(),
                        e
                    ),
                }
            }
        });

        Self {
            proxy_mode: cfg.proxy_mode.clone(),
            local_node: cfg.local_node.clone(),
            tx,
        }
    }

    // Determine if we should prefetch a certificate for this workload. Being "wrong" is not
    // too bad; a missing cert will be fetched on-demand when we get a request, so will just
    // result in some extra latency.
    // 确定是否我们应该预取一个cert，为这个workload，错了不会太差，一个丢失的cert会按需拉取，当我们有一个request，这样
    // 会导致额外的latency
    fn should_prefetch_certificate(&self, w: &Workload) -> bool {
        // Only shared mode fetches other workloads's certs
        // 只有shared mode拉取其他workloads的certs
        self.proxy_mode == ProxyMode::Shared &&
            // We only get certs for our own node
            // 我们只为自己的node获取certs
            Some(&w.node) == self.local_node.as_ref() &&
            // If it doesn't support HBONE it *probably* doesn't need a cert.
            // 如果不支持HBONE，可能不需要一个cert
            (w.native_tunnel || w.protocol == Protocol::HBONE)
    }
}

impl CertFetcher for CertFetcherImpl {
    fn prefetch_cert(&self, w: &Workload) {
        if self.should_prefetch_certificate(w) {
            if let Err(e) = self.tx.try_send(w.identity()) {
                info!("couldn't prefetch: {:?}", e)
            }
        }
    }
}
