use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use super::acceptor::ProxyMode;
use super::{acceptor::WrappedIncoming, config::LoadedTlsBundle, handler::KeyhouseService};
use crate::keyhouse::kms_server::KmsServer;
use crate::prelude::*;
use crate::KeyhouseImpl;
use crate::SERVER_CONFIG;
use spire_workload::Identity;
use tokio::fs;
use tokio::time::{sleep, Duration};
use tonic::transport::{Server, ServerTlsConfig};

async fn conn_count_reporter<T: KeyhouseImpl + 'static>(conn_count: Arc<AtomicU64>) {
    loop {
        let count = conn_count.load(Ordering::SeqCst);
        T::KeyhouseExt::emit_metric(Metric::ConnCount(count));
        sleep(Duration::from_secs(15)).await;
    }
}

pub async fn start_server<T: KeyhouseImpl + 'static>(
    address: &str,
    tls_config: rustls::ServerConfig,
    service: KeyhouseService<T>,
) -> Result<()> {
    info!("KeyhouseServer listening on {}", address);
    let mut tls = ServerTlsConfig::new();
    tls.rustls_server_config(tls_config);
    service.prepare_start().await?;
    info!("service extension started");
    let keepalive = std::time::Duration::from_secs(10);
    let proxy_mode = {
        let config = &SERVER_CONFIG.get().0;
        if config.force_proxy_header {
            ProxyMode::Require
        } else if config.allow_proxy_header {
            ProxyMode::Accept
        } else {
            ProxyMode::None
        }
    };
    let incoming = WrappedIncoming::new(address.parse()?, true, Some(keepalive), proxy_mode)?;

    tokio::spawn(conn_count_reporter::<T>(incoming.get_conn_count()));

    info!("data plane spawned");

    Server::builder()
        .tls_config(tls)?
        .tcp_keepalive(Some(keepalive))
        .timeout(std::time::Duration::from_secs(30))
        .add_service(KmsServer::new(service))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

fn parse_certs(der_string: &String) -> Result<Vec<rustls::Certificate>> {
    let res: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut der_string.as_bytes())?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();

    Ok(res)
}

fn parse_pkcs8_private_keys(key_string: &String) -> Result<Vec<rustls::PrivateKey>> {
    let res: Vec<rustls::PrivateKey> =
        rustls_pemfile::pkcs8_private_keys(&mut key_string.as_bytes())?
            .iter()
            .map(|v| rustls::PrivateKey(v.clone()))
            .collect();

    Ok(res)
}

pub async fn prepare_bundle(bundle: &LoadedTlsBundle) -> Result<Arc<Identity>> {
    let bundle_str = fs::read_to_string(&bundle.ca_path).await?;
    let certs_str = fs::read_to_string(&bundle.cert_path).await?;
    let key_str = fs::read_to_string(&bundle.key_path).await?;
    let loaded_bundle = spire_workload::Identity::from_rustls(
        parse_certs(&bundle_str).map_err(|_| anyhow!("failed to load bundle"))?,
        parse_certs(&certs_str).map_err(|_| anyhow!("failed to load certs"))?,
        parse_pkcs8_private_keys(&key_str)
            .ok()
            .map(|x| x.into_iter().next())
            .flatten()
            .ok_or_else(|| anyhow!("failed to load private key"))?,
    )?;
    Ok(Arc::new(loaded_bundle))
}

pub async fn init_spire_workload() -> Result<()> {
    let config = &SERVER_CONFIG.get().1;
    let mut wanted_identities = vec![];
    let mut identity_count = 2;
    let mut is_mocked = false;
    if let Some(_bundle) = &config.server_bundle {
        identity_count -= 1;
        is_mocked = true;
    } else {
        wanted_identities.push(config.server_identity.clone());
    }
    if let Some(_bundle) = &config.internal_server_bundle {
        identity_count -= 1;
        is_mocked = true;
    } else if config.server_identity == config.internal_server_identity {
        identity_count -= 1;
    } else {
        wanted_identities.push(config.internal_server_identity.clone());
    }
    let identity_out = wanted_identities
        .into_iter()
        .map(|x| format!("'{}'", x))
        .collect::<Vec<_>>()
        .join(", ");

    if identity_count > 0 {
        if is_mocked {
            return Err(anyhow!(
                "cannot mocked (static) spire bundle with live spire bundle"
            ));
        }
        spire_workload::init();
        loop {
            let identities = spire_workload::IDENTITIES.load();
            if identities.len() >= identity_count {
                break;
            }
            info!("waiting for identities to load: {}", identity_out);
            let current_identities = identities
                .keys()
                .map(|x| format!("'{}'", x))
                .collect::<Vec<_>>()
                .join(", ");
            info!(
                "currently have {} identities: {}",
                identities.len(),
                current_identities
            );

            sleep(Duration::from_secs(1)).await;
        }
    }
    if is_mocked {
        info!("using mocked spire workload");
        let mut identities = BTreeMap::new();
        if let Some(bundle) = &config.server_bundle {
            let loaded_bundle = prepare_bundle(bundle).await?;
            identities.insert(config.server_identity.clone(), loaded_bundle);
        }
        if let Some(bundle) = &config.internal_server_bundle {
            let loaded_bundle = prepare_bundle(bundle).await?;
            identities.insert(config.internal_server_identity.clone(), loaded_bundle);
        }
        spire_workload::init_mock(identities, vec![])
    }
    Ok(())
}
