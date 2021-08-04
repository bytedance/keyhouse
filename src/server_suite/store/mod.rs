mod customer_key;
mod impls;
pub mod intermediate_key;
mod keyring;
mod secret;
#[cfg(test)]
mod tests;

use crate::prelude::*;
use crate::util;
use crate::KeyhouseImpl;
use serde::{Deserialize, Serialize};
use spire_workload::SpiffeIDMatcher;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use uuid::Uuid;

pub use customer_key::*;
pub use impls::EtcdStore;
pub use impls::MemStore;
pub use impls::MockStore;
pub use impls::{MaskMode, MaskStore};
pub use intermediate_key::IntermediateKey;
pub use keyring::*;
pub use secret::{DecodedSecret, Secret};
use tokio::sync::{mpsc, oneshot};

pub type OwnedStore<T> = Arc<dyn Store<T> + Send + Sync + 'static>;

#[tonic::async_trait]
pub trait Store<T: KeyhouseImpl + 'static> {
    /// no operation on primary stores, reloads caches
    async fn reload(&self) -> Result<()>;

    async fn get_customer_key_by_id(&self, id: u32) -> Result<Option<CustomerKey>>;

    async fn get_customer_key_by_alias(&self, alias: &str) -> Result<Option<CustomerKey>>;

    async fn mutate_customer_key(
        &self,
        id: u32,
        mutation: CustomerKeyMutation,
    ) -> Result<CustomerKey>;

    async fn reencode_customer_key(
        &self,
        id: u32,
        old_sensitives: Sensitives,
        new_sensitives: Sensitives,
        updated_at: Option<u64>,
    ) -> Result<CustomerKey>;

    async fn get_all_customer_keys_by_acl_component(
        &self,
        domain: Option<AccessControlDomain>,
        component_name: &str,
        component_value: Option<&str>,
    ) -> Result<Vec<CustomerKey>>;

    async fn get_all_customer_keys(&self) -> Result<HashMap<u32, CustomerKey>>;

    async fn get_all_customer_key_aliases(&self) -> Result<HashMap<String, HashMap<String, u32>>>;

    async fn store_customer_key(&self, key: CustomerKey) -> Result<()>;

    async fn store_keyring(&self, keyring: Keyring) -> Result<()>;

    async fn get_keyring(&self, alias: &str) -> Result<Option<Keyring>>;

    async fn get_keyring_keys(&self, alias: &str) -> Result<Vec<CustomerKey>>;

    async fn get_all_keyrings(&self) -> Result<HashMap<String, Keyring>>;

    async fn get_intermediate_key(&self) -> Result<Option<IntermediateKey>>;

    async fn set_intermediate_key(
        &self,
        old_key: Option<IntermediateKey>,
        new_key: IntermediateKey,
    ) -> Result<()>;

    async fn get_secret(&self, alias: &str) -> Result<Option<Secret>>;

    async fn delete_secret(&self, alias: &str) -> Result<bool>;

    async fn get_key_secrets(&self, alias: &str) -> Result<Vec<Secret>>;

    async fn count_key_secrets(&self, alias: &str) -> Result<usize>;

    async fn store_secret(&self, previous_secret: Option<Secret>, secret: Secret) -> Result<()>;

    async fn get_all_secrets(&self) -> Result<HashMap<String, HashMap<String, Secret>>>;

    async fn hook_updates(&self, sender: mpsc::Sender<StoreUpdate>) -> Result<()>;

    async fn cache_invalidation(
        &self,
        invalidation: &CacheInvalidation,
    ) -> Result<Option<StoreUpdateData>>;
}

#[derive(Debug, PartialEq, Clone)]
pub enum StoreUpdateData {
    NewKey(CustomerKey),
    KeyMutation {
        id: u32,
        mutation: CustomerKeyMutation,
    },
    KeyEncoded {
        id: u32,
        sensitives: Sensitives,
    },
    CacheInvalidate(CustomerKey), // updates the key under given id
    NewKeyring(Keyring),
    CacheInvalidateKeyring(Keyring),
    UpdateIntermediateKey(IntermediateKey),
    CacheInvalidateIntermediateKey(IntermediateKey),
    StoreSecret(Secret),
    CacheInvalidateSecret(Secret),
    DeleteSecret(String), // alias
}

#[derive(Debug, PartialEq, Clone)]
pub enum CacheInvalidation {
    Key { id: u32 },
    Keyring { alias: String },
    IntermediateKey,
    Secret { alias: String },
}

pub struct StoreUpdate {
    data: StoreUpdateData,
    result: Option<oneshot::Sender<Result<()>>>,
}
