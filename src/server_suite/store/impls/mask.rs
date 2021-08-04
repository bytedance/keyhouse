use super::*;
use crate::prelude::*;

pub enum MaskMode {
    Config,
    ReadOnly,
}

pub struct MaskStore<T: KeyhouseImpl + 'static>(OwnedStore<T>, MaskMode);

impl<T: KeyhouseImpl + 'static> MaskStore<T> {
    pub fn new(inner: OwnedStore<T>, mode: MaskMode) -> Self {
        MaskStore(inner, mode)
    }

    fn is_read_only(&self) -> bool {
        match self.1 {
            MaskMode::Config => crate::SERVER_CONFIG.get().0.read_only,
            MaskMode::ReadOnly => true,
        }
    }

    fn check_read_only(&self) -> Result<()> {
        if self.is_read_only() {
            return Err(anyhow!("keyhouse is in read only mode"));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl<T: KeyhouseImpl + 'static> Store<T> for MaskStore<T> {
    async fn reload(&self) -> Result<()> {
        self.0.reload().await
    }

    #[allow(clippy::map_clone)]
    async fn get_customer_key_by_id(&self, id: u32) -> Result<Option<CustomerKey>> {
        self.0.get_customer_key_by_id(id).await
    }

    #[allow(clippy::map_clone)]
    async fn get_customer_key_by_alias(&self, alias: &str) -> Result<Option<CustomerKey>> {
        self.0.get_customer_key_by_alias(alias).await
    }

    async fn mutate_customer_key(
        &self,
        id: u32,
        mutation: CustomerKeyMutation,
    ) -> Result<CustomerKey> {
        self.check_read_only()?;
        self.0.mutate_customer_key(id, mutation).await
    }

    async fn reencode_customer_key(
        &self,
        id: u32,
        old_sensitives: Sensitives,
        new_sensitives: Sensitives,
        updated_at: Option<u64>,
    ) -> Result<CustomerKey> {
        self.check_read_only()?;
        self.0
            .reencode_customer_key(id, old_sensitives, new_sensitives, updated_at)
            .await
    }

    async fn get_all_customer_keys_by_acl_component(
        &self,
        domain: Option<AccessControlDomain>,
        component_name: &str,
        component_value: Option<&str>,
    ) -> Result<Vec<CustomerKey>> {
        self.0
            .get_all_customer_keys_by_acl_component(domain, component_name, component_value)
            .await
    }

    async fn get_all_customer_keys(&self) -> Result<HashMap<u32, CustomerKey>> {
        self.0.get_all_customer_keys().await
    }

    async fn get_all_customer_key_aliases(&self) -> Result<HashMap<String, HashMap<String, u32>>> {
        self.0.get_all_customer_key_aliases().await
    }

    async fn store_customer_key(&self, key: CustomerKey) -> Result<()> {
        self.check_read_only()?;
        self.0.store_customer_key(key).await
    }

    async fn store_keyring(&self, keyring: Keyring) -> Result<()> {
        self.check_read_only()?;
        self.0.store_keyring(keyring).await
    }

    async fn get_keyring(&self, alias: &str) -> Result<Option<Keyring>> {
        self.0.get_keyring(alias).await
    }

    async fn get_keyring_keys(&self, alias: &str) -> Result<Vec<CustomerKey>> {
        self.0.get_keyring_keys(alias).await
    }

    async fn get_all_keyrings(&self) -> Result<HashMap<String, Keyring>> {
        self.0.get_all_keyrings().await
    }

    async fn get_intermediate_key(&self) -> Result<Option<IntermediateKey>> {
        self.0.get_intermediate_key().await
    }

    async fn set_intermediate_key(
        &self,
        old_key: Option<IntermediateKey>,
        new_key: IntermediateKey,
    ) -> Result<()> {
        self.check_read_only()?;
        self.0.set_intermediate_key(old_key, new_key).await
    }

    async fn get_secret(&self, alias: &str) -> Result<Option<Secret>> {
        self.0.get_secret(alias).await
    }

    async fn delete_secret(&self, alias: &str) -> Result<bool> {
        self.check_read_only()?;
        self.0.delete_secret(alias).await
    }

    async fn get_key_secrets(&self, alias: &str) -> Result<Vec<Secret>> {
        self.0.get_key_secrets(alias).await
    }

    async fn count_key_secrets(&self, alias: &str) -> Result<usize> {
        self.0.count_key_secrets(alias).await
    }

    async fn store_secret(&self, previous_secret: Option<Secret>, secret: Secret) -> Result<()> {
        self.check_read_only()?;
        self.0.store_secret(previous_secret, secret).await
    }

    async fn get_all_secrets(&self) -> Result<HashMap<String, HashMap<String, Secret>>> {
        self.0.get_all_secrets().await
    }

    async fn hook_updates(&self, sender: mpsc::Sender<StoreUpdate>) -> Result<()> {
        self.0.hook_updates(sender).await
    }

    async fn cache_invalidation(
        &self,
        invalidation: &CacheInvalidation,
    ) -> Result<Option<StoreUpdateData>> {
        self.0.cache_invalidation(invalidation).await
    }
}
