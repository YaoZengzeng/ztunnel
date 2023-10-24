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

use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, trace, warn, Instrument};

use crate::config::ProxyMode;
use crate::proxy::metrics::Reporter;
use crate::proxy::outbound::OutboundConnection;
use crate::proxy::{metrics, util, ProxyInputs};
use crate::proxy::{Error, TraceParent};
use crate::rbac;
use crate::state::workload::NetworkAddress;
use crate::{proxy, socket};

pub(super) struct InboundPassthrough {
    listener: TcpListener,
    pi: ProxyInputs,
}

impl InboundPassthrough {
    pub(super) async fn new(mut pi: ProxyInputs) -> Result<InboundPassthrough, Error> {
        let listener: TcpListener = TcpListener::bind(pi.cfg.inbound_plaintext_addr)
            .await
            .map_err(|e| Error::Bind(pi.cfg.inbound_plaintext_addr, e))?;
        let transparent = super::maybe_set_transparent(&pi, &listener)?;
        // Override with our explicitly configured setting
        pi.cfg.enable_original_source = Some(transparent);

        info!(
            address=%listener.local_addr().unwrap(),
            // plaintext
            component="inbound plaintext",
            transparent,
            "listener established",
        );
        Ok(InboundPassthrough { listener, pi })
    }

    pub(super) async fn run(self) {
        loop {
            // Asynchronously wait for an inbound socket.
            // 异步等待一个inbound socket
            let socket = self.listener.accept().await;
            let pi = self.pi.clone();
            match socket {
                Ok((stream, remote)) => {
                    tokio::spawn(async move {
                        if let Err(e) = Self::proxy_inbound_plaintext(
                            pi, // pi cloned above; OK to move
                            socket::to_canonical(remote),
                            stream,
                        )
                        .await
                        {
                            warn!(source=%socket::to_canonical(remote), component="inbound plaintext", "proxying failed: {}", e)
                        }
                    }.in_current_span());
                }
                Err(e) => {
                    if util::is_runtime_shutdown(&e) {
                        return;
                    }
                    error!("Failed TCP handshake {}", e);
                }
            }
        }
    }

    async fn proxy_inbound_plaintext(
        pi: ProxyInputs,
        source: SocketAddr,
        mut inbound: TcpStream,
    ) -> Result<(), Error> {
        let orig = socket::orig_dst_addr_or_default(&inbound);
        // Check if it is a recursive call when proxy mode is Node.
        // 检查是否是一个递归调用，当proxy模式为Node时
        if pi.cfg.proxy_mode == ProxyMode::Shared && Some(orig.ip()) == pi.cfg.local_ip {
            return Err(Error::SelfCall);
        }
        info!(%source, destination=%orig, component="inbound plaintext", "accepted connection");
        let network_addr = NetworkAddress {
            // inbound request必须在我们的network
            network: pi.cfg.network.clone(), // inbound request must be on our network
            address: orig.ip(),
        };
        // 根据network_addr获取workload
        let Some(upstream) = pi.state.fetch_workload(&network_addr).await else {
            return Err(Error::UnknownDestination(orig.ip()));
        };
        if upstream.waypoint.is_some() {
            // This is an inbound request not over HBONE, but we have a waypoint.
            // 这是一个inbound request，但是没有通过HBONE，但是我们有一个waypoint
            // The request needs to go through the waypoint for policy enforcement.
            // 这个request需要通过waypoint用于policy执行
            // This can happen from clients that are not part of the mesh; they won't know to send
            // to the waypoint.
            // 这可以来自不是mesh的网格，他们不知道要发往waypoint
            // To handle this, we forward it to the waypoint ourselves, which will hairpin back to us.
            // 为了处理这种情况，我们自己将它发往waypoint，最后会转回到我们自己
            let mut oc = OutboundConnection {
                pi: pi.clone(),
                id: TraceParent::new(),
            };
            // Spoofing the source IP only works when the destination or the source are on our node.
            // In this case, the source and the destination might both be remote, so we need to disable it.
            oc.pi.cfg.enable_original_source = Some(false);
            return oc.proxy_to(inbound, source.ip(), orig, false).await;
        }

        // We enforce RBAC only for non-hairpin cases. This is because we may not be able to properly
        // enforce the policy (for example, if it has L7 attributes), while waypoint will.
        // 对于non-hairpin类型，我们只执行non-hairpin，这是因为我们不能很好地执行policy（例如，如果他有L7 attributes），而waypoint会做
        // Instead, we skip enforcement and forward to the waypoint to enforce.
        // 相反，我们跳过enforcement并且转发到waypoint去执行
        // On the inbound HBONE side, we will validate it came from the waypoint (and therefor had enforcemen).
        // 在inbound HBONE端，我们会校验它来自waypoint（因此有enforcement）
        let conn = rbac::Connection {
            src_identity: None,
            src_ip: source.ip(),
            // inbound request must be on our network since this is passthrough
            // rather than HBONE, which can be tunneled across networks through gateways.
            // by definition, without the gateway our source must be on our network.
            // inbound request必须在我们的network，因为它是passthrough而不是HBONE
            dst_network: pi.cfg.network.clone(),
            dst: orig,
        };
        if !pi.state.assert_rbac(&conn).await {
            info!(%conn, "RBAC rejected");
            return Ok(());
        }
        // 获取original地址
        let source_ip = super::get_original_src_from_stream(&inbound);
        let orig_src = pi
            .cfg
            .enable_original_source
            .unwrap_or_default()
            .then_some(source_ip)
            .flatten();
        trace!(%source, destination=%orig, component="inbound plaintext", "connect to {orig:?} from {orig_src:?}");
        // 构建outbound
        let mut outbound = super::freebind_connect(orig_src, orig).await?;
        trace!(%source, destination=%orig, component="inbound plaintext", "connected");

        // Find source info. We can lookup by XDS or from connection attributes
        // 查找source info，我们可以通过XDS或者connection attributes查找
        let source_workload = if let Some(source_ip) = source_ip {
            let network_addr_srcip = NetworkAddress {
                // inbound request must be on our network since this is passthrough
                // rather than HBONE, which can be tunneled across networks through gateways.
                // by definition, without the gateway our source must be on our network.
                network: pi.cfg.network.clone(),
                address: source_ip,
            };
            pi.state.fetch_workload(&network_addr_srcip).await
        } else {
            None
        };
        let derived_source = metrics::DerivedWorkload {
            identity: conn.src_identity,
            ..Default::default()
        };
        let connection_metrics = metrics::ConnectionOpen {
            reporter: Reporter::destination,
            source: source_workload,
            derived_source: Some(derived_source),
            destination: Some(upstream),
            connection_security_policy: metrics::SecurityPolicy::unknown,
            destination_service: None,
        };
        let _connection_close = pi
            .metrics
            .increment_defer::<_, metrics::ConnectionClose>(&connection_metrics);
        let transferred_bytes = metrics::BytesTransferred::from(&connection_metrics);
        // 在inbound和outbound之间传递数据
        proxy::relay(&mut outbound, &mut inbound, &pi.metrics, transferred_bytes).await?;
        // 完成inbound plaintext
        info!(%source, destination=%orig, component="inbound plaintext", "connection complete");
        Ok(())
    }
}
