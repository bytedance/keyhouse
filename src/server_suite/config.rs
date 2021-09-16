use crate::util::dynamic_config::DynamicConfig;

use crate::prelude::*;
use serde::{Deserialize, Serialize};
use spire_workload::{SpiffeID, SpiffeIdAuthorizer};
use std::convert::TryFrom;
use url::Url;

lazy_static! {
    static ref CONFIG_YAML: String =
        std::env::var("KH_CONF").unwrap_or_else(|_| "conf/server_config.yaml".to_string());
}

fn make_default_u64<const V: u64>() -> u64 {
    V
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RawConfig {
    pub server_identity: String,
    pub server_bundle_path: Option<String>,
    pub internal_server_identity: Option<String>,
    pub internal_server_bundle_path: Option<String>,
    pub etcd_identity: Option<String>,
    pub etcd_addresses: Vec<Url>,
    pub etcd_username: Option<String>,
    pub etcd_password: Option<String>,
    pub etcd_max_refresh_rate_ms: u64,
    pub etcd_min_refresh_rate_ms: u64,
    pub etcd_prefix: Option<String>,
    #[serde(default = "make_default_u64::<60000>")]
    pub etcd_operation_timeout_ms: u64,
    pub sentry: Option<Url>,
    pub server_address: String,
    pub server_port: u16,
    pub control_plane_ip: String,
    pub region: String,
    pub read_only: bool,
    pub enable_control_plane_tls: bool,
    pub health_check_ip: Option<String>,
    pub secret_limit: Option<usize>,
    pub customer_key_limit: Option<usize>,
    pub acl_limit: Option<usize>,
    pub master_key_id: String,
    #[serde(default)]
    pub force_proxy_header: bool,
    #[serde(default)]
    pub allow_proxy_header: bool,
    #[serde(default = "make_default_u64::<86400>")]
    pub intermediate_key_rotation_seconds: u64,
    #[serde(default = "make_default_u64::<31536000>")]
    pub customer_key_rotation_seconds: u64,
    #[serde(default = "make_default_u64::<1>")]
    pub customer_key_rotation_throttle_qps: u64,
}

#[derive(Clone)]
pub struct LoadedTlsBundle {
    pub ca_path: String,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Clone)]
pub struct Config {
    pub server_identity: SpiffeID,
    pub internal_server_identity: SpiffeID,
    pub etcd_identity: Option<SpiffeID>,
    pub server_bundle: Option<LoadedTlsBundle>,
    pub internal_server_bundle: Option<LoadedTlsBundle>,
    pub etcd_prefix: String,
}

impl LoadedTlsBundle {
    pub fn new(bundle_path: &str) -> LoadedTlsBundle {
        let ca_path = bundle_path.to_string() + "ca.crt";
        let cert_path = bundle_path.to_string() + "cert.pem";
        let key_path = bundle_path.to_string() + "key.pem";
        LoadedTlsBundle {
            ca_path,
            cert_path,
            key_path,
        }
    }
}

impl TryFrom<RawConfig> for Config {
    type Error = Error;

    fn try_from(raw: RawConfig) -> Result<Config> {
        let server_bundle = raw.server_bundle_path.as_deref().map(LoadedTlsBundle::new);
        let internal_server_bundle = raw
            .internal_server_bundle_path
            .as_deref()
            .map(LoadedTlsBundle::new);

        let server_identity = SpiffeID::new(raw.server_identity.parse()?)?;
        let internal_server_identity = SpiffeID::new(
            raw.internal_server_identity
                .as_deref()
                .unwrap_or(&raw.server_identity)
                .parse()?,
        )?;
        let etcd_identity = raw
            .etcd_identity
            .map(|x| SpiffeID::new(x.parse()?))
            .transpose()?;

        Ok(Config {
            etcd_prefix: raw.etcd_prefix.unwrap_or_else(|| "".to_string()),
            server_bundle,
            internal_server_bundle,
            server_identity,
            internal_server_identity,
            etcd_identity,
        })
    }
}

impl Config {
    pub fn server_tls_config(&self) -> rustls::ServerConfig {
        spire_workload::make_server_config(
            Some(self.server_identity.clone()),
            &[b"h2".to_vec(), b"http/1.1".to_vec()],
            Box::new(true),
            false,
        )
    }

    pub fn internal_client_tls_config(
        &self,
        authorizer: Box<dyn SpiffeIdAuthorizer>,
        require_server_auth: bool,
    ) -> rustls::ClientConfig {
        spire_workload::make_client_config(
            Some(self.internal_server_identity.clone()),
            &[b"h2".to_vec(), b"http/1.1".to_vec()],
            authorizer,
            require_server_auth,
        )
    }

    pub fn etcd_client_tls_config(&self) -> rustls::ClientConfig {
        self.internal_client_tls_config(
            if let Some(etcd_identity) = self.etcd_identity.clone() {
                Box::new(etcd_identity)
            } else {
                Box::new(true)
            },
            self.etcd_identity.is_some(),
        )
    }
}

lazy_static! {
    pub static ref SERVER_CONFIG: DynamicConfig<RawConfig, Config> =
        DynamicConfig::new(CONFIG_YAML.to_string(), true).expect("failed to load server config");
}
