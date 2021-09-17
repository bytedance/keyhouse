use crate::server_suite::config::SERVER_CONFIG;
use crate::server_suite::store;
use crate::{prelude::*, server_suite};
use std::sync::Arc;

#[cfg(feature = "spawn_controlplane")]
use crate::{control, control::auth::ControlPlaneAuth};

#[cfg(feature = "spawn_dataplane")]
use crate::server_suite::{handler::KeyhouseService, server::start_server};

pub fn entrypoint<T: KeyhouseImpl + 'static>() {
    let sentry_configuration = &SERVER_CONFIG.get().0.sentry;
    if let Some(sentry_configuration) = sentry_configuration {
        let _sentry = sentry::init((
            sentry_configuration.to_string(),
            sentry::ClientOptions {
                release: sentry::release_name!(),
                ..Default::default()
            },
        ));
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Tokio runtime initialization failed!")
        .block_on(async_entrypoint::<T>())
}

pub async fn async_entrypoint<T: KeyhouseImpl + 'static>() {
    T::KeyhouseExt::pre_service_load::<T>().await;

    info!("service extension preloaded");

    server_suite::server::init_spire_workload()
        .await
        .expect("failed to initialize spire_workload");

    info!("spire workload initialized");

    info!("loading main store");
    let mem_store = {
        let config = &SERVER_CONFIG.get();

        debug!("connecting to etcd");

        let etcd_store = store::EtcdStore::<T>::new(
            config.1.etcd_prefix.clone(),
            config.0.etcd_addresses.clone(),
            config.1.etcd_client_tls_config(),
            match (
                config.0.etcd_username.as_ref(),
                config.0.etcd_password.as_ref(),
            ) {
                (Some(username), Some(password)) => Some((username.clone(), password.clone())),
                _ => None,
            },
        )
        .await
        .expect("failed to connect to etcd");

        debug!("etcd connected. creating memstore");

        store::MemStore::new(
            Arc::new(etcd_store),
            config.0.etcd_max_refresh_rate_ms,
            config.0.etcd_min_refresh_rate_ms,
        )
        .await
        .expect("failed to init cache")
    };

    info!("main store loaded");

    let store = Arc::new(store::MaskStore::new(mem_store, store::MaskMode::Config));

    server_suite::store::intermediate_key::IntermediateKey::reload_checked(store.clone())
        .await
        .expect("failed to initially load intermediate key");

    info!("initialized intermediate key");

    #[cfg(feature = "spawn_controlplane")]
    {
        info!("feature spawn_controlplane enabled. spawning controlplane");
        control::spawn_control(
            store.clone(),
            Arc::new(*T::ControlPlaneAuth::new().expect("failed to init control plane auth")),
        );

        info!("controlplane spawned");
    }

    #[cfg(not(feature = "spawn_controlplane"))]
    info!("feature spawn_controlplane disabled. skipped controlplane");

    #[cfg(feature = "spawn_dataplane")]
    {
        let tls_config = SERVER_CONFIG.get().1.server_tls_config();
        let (ip, port) = {
            let c = &SERVER_CONFIG.get().0;
            (c.server_address.clone(), c.server_port)
        };
        let addr = format!("{}:{}", ip, port);
        info!("feature spawn_dataplane enabled. spawning dataplane");
        start_server(&addr, tls_config, KeyhouseService::new(store))
            .await
            .unwrap();
    }

    #[cfg(not(feature = "spawn_dataplane"))]
    info!("feature spawn_dataplane disabled. skipped dataplane");
}
