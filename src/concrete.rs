use std::marker::PhantomData;

use crate::baseclient::ClientCoding;
use crate::control::ControlPlaneAuth;
use crate::event::LogEvent;
use crate::prelude::*;
use crate::{
    master_key::mock::MockMasterKey,
    master_key::MasterKeyProvider,
    server_suite::coding::CodingItem,
    store::{CustomerKey, OwnedStore},
};
use actix_web::Route;
use spire_workload::SpiffeID;

pub trait KeyhouseImpl: Send + Sync + Clone + std::fmt::Debug {
    type MasterKeyProvider: MasterKeyProvider + 'static;
    type CustomerItem: CodingItem + 'static;
    type IntermediateItem: CodingItem + 'static;
    type ClientCoding: ClientCoding + 'static;
    type ControlPlaneAuth: ControlPlaneAuth + 'static;
    type AlternateDataAuthToken: AlternateDataAuthToken + 'static;
    type AlternateDataAuthProvider: AlternateDataAuthProvider<Self::AlternateDataAuthToken>
        + 'static;
    type KeyhouseExt: KeyhouseExt + 'static;
}

impl KeyhouseImpl for () {
    type MasterKeyProvider = MockMasterKey;
    type CustomerItem = ();
    type IntermediateItem = ();
    type ClientCoding = ();
    type ControlPlaneAuth = crate::control::MockAuth;
    type AlternateDataAuthToken = ();
    type AlternateDataAuthProvider = ();
    type KeyhouseExt = ();
}

pub enum Metric {
    DataQueryComplete {
        latency: f64,
        success: bool,
        auth_service: String,
        auth_user: String,
        status: String,
        target_alias: String,
        endpoint: String,
    },
    ControlQueryComplete {
        latency: f64,
        success: bool,
        endpoint: String,
    },
    CustomerKeyReissued,
    CustomerKeyReencoded,
    IntermediateKeyReissued,
    CacheFullReload,
    CachePartialReload,
    CacheUpdateReceived,
    EtcdOperation {
        latency: f64,
        success: bool,
        method: &'static str,
    },
    EtcdCustomerKeyUpdateReceived,
    EtcdIntermediateKeyUpdateReceived,
    EtcdKeyringUpdateReceived,
    EtcdSecretUpdateReceived,
    ConnCount(u64),
}

#[tonic::async_trait]
pub trait KeyhouseExt: Send + Sync {
    fn add_extended_routes<T: KeyhouseImpl + 'static>() -> Vec<(String, Route)>;

    async fn service_load<T: KeyhouseImpl + 'static>(store: OwnedStore<T>) -> Result<()>;

    async fn pre_service_load<T: KeyhouseImpl + 'static>();

    fn emit_metric(value: Metric);

    fn emit_event(event: &LogEvent);

    // used for indexing, etc
    fn customer_key_metadata_refresh(key: &CustomerKey);

    fn get_spiffe_service_user(id: &SpiffeID) -> (Option<String>, Option<String>); // service, username

    // should be lowest cardinality component of spiffe id schema (most uniqueish) for best performance
    fn get_spiffe_primary_component() -> String;

    fn region_url(region: &[u8]) -> Option<String>;

    fn region_from_name(region_name: &str) -> Option<Vec<u8>>;
}

#[tonic::async_trait]
impl KeyhouseExt for () {
    fn add_extended_routes<T: KeyhouseImpl + 'static>() -> Vec<(String, Route)> {
        vec![]
    }

    async fn service_load<T: KeyhouseImpl + 'static>(_store: OwnedStore<T>) -> Result<()> {
        Ok(())
    }

    async fn pre_service_load<T: KeyhouseImpl + 'static>() {
        let mut builder = env_logger::Builder::from_env(
            env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
        );
        builder.filter_module("rustls::server::tls13", log::LevelFilter::Error);

        builder.init();
    }

    fn emit_metric(_value: Metric) {}

    fn emit_event(_event: &LogEvent) {}

    fn customer_key_metadata_refresh(_key: &CustomerKey) {}

    fn get_spiffe_service_user(_id: &SpiffeID) -> (Option<String>, Option<String>) {
        (None, None)
    }

    fn get_spiffe_primary_component() -> String {
        "id".to_string()
    }

    fn region_url(region: &[u8]) -> Option<String> {
        Some(format!("https://{}", String::from_utf8_lossy(region)))
    }

    fn region_from_name(region_name: &str) -> Option<Vec<u8>> {
        Some(region_name.as_bytes().to_vec())
    }
}

pub trait AlternateDataAuthProvider<T: AlternateDataAuthToken + 'static>: Send + Sync {
    fn authenticate_customer_key_token(token: &str) -> Option<T>;
}

pub struct DualAlternateDataAuthProvider<
    T1: AlternateDataAuthToken + 'static,
    P1: AlternateDataAuthProvider<T1> + 'static,
    T2: AlternateDataAuthToken + Into<T1> + 'static,
    P2: AlternateDataAuthProvider<T2> + 'static,
> {
    _first: P1,
    _second: P2,
    _1: PhantomData<T1>,
    _2: PhantomData<T2>,
}

impl<
        T1: AlternateDataAuthToken + 'static,
        P1: AlternateDataAuthProvider<T1> + 'static,
        T2: AlternateDataAuthToken + Into<T1> + 'static,
        P2: AlternateDataAuthProvider<T2> + 'static,
    > AlternateDataAuthProvider<T1> for DualAlternateDataAuthProvider<T1, P1, T2, P2>
{
    fn authenticate_customer_key_token(token: &str) -> Option<T1> {
        if let Some(first) = P1::authenticate_customer_key_token(token) {
            Some(first)
        } else {
            P2::authenticate_customer_key_token(token).map(|second| second.into())
        }
    }
}

impl AlternateDataAuthProvider<()> for () {
    fn authenticate_customer_key_token(_token: &str) -> Option<()> {
        None
    }
}

pub trait AlternateDataAuthToken: serde::Serialize + Send + Sync {
    #[allow(clippy::wrong_self_convention)]
    fn into_spiffe_id(&self) -> Option<SpiffeID>;

    fn username(&self) -> Option<String>;
    fn service(&self) -> Option<String>;

    fn is_service(&self) -> bool;
}

impl AlternateDataAuthToken for () {
    fn into_spiffe_id(&self) -> Option<SpiffeID> {
        None
    }

    fn username(&self) -> Option<String> {
        None
    }

    fn service(&self) -> Option<String> {
        None
    }

    fn is_service(&self) -> bool {
        true
    }
}
