use super::*;
use crate::{prelude::*, Metric};
use arc_swap::ArcSwap;
use futures::FutureExt;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{self, sleep, Duration, Instant};

/// stores a snapshot of the cache data
#[derive(Clone)]
struct MemStoreInstant {
    keys: HashMap<u32, CustomerKey>,
    aliases: HashMap<String, HashMap<String, u32>>,
    keyrings: HashMap<String, Keyring>,
    intermediate_key: Option<IntermediateKey>,
    secrets: HashMap<String, HashMap<String, Secret>>,
    // svid component -> value or wildcard -> access control domain -> set of customer key ids
    derived_acl_index:
        HashMap<(String, Option<String>), BTreeMap<AccessControlDomain, BTreeSet<u32>>>,
}

impl MemStoreInstant {
    /// differential updates between full flushes use this
    fn apply_update<T: KeyhouseImpl + 'static>(&mut self, update: StoreUpdateData) -> Result<()> {
        match update {
            StoreUpdateData::KeyMutation { id, mutation } => {
                let initial_key: CustomerKey;
                let final_key: CustomerKey;
                match self.keys.get_mut(&id) {
                    Some(key) => {
                        initial_key = key.clone();
                        key.apply_mutation(mutation);
                        final_key = key.clone();
                    }
                    None => {
                        return Err(anyhow!("no key found in cache"));
                    }
                }
                // post update
                self.update_derived_cache_for_key(&initial_key, &final_key);
                T::KeyhouseExt::customer_key_metadata_refresh(&final_key);
            }
            StoreUpdateData::KeyEncoded { id, sensitives } => match self.keys.get_mut(&id) {
                Some(customer_key) => {
                    customer_key.sensitives = Some(sensitives);
                }
                None => {
                    return Err(anyhow!("no key found in cache"));
                }
            },
            // NewKey is equivalent to CacheInvalidate but only used at the caching layer
            // and NewKey has much lower latency -- CacheInvalidate is the authoritative update though.
            StoreUpdateData::NewKey(key) | StoreUpdateData::CacheInvalidate(key) => {
                let (keyring_alias, key_alias) = split_alias(&key.alias);
                if !self.aliases.contains_key(keyring_alias) {
                    self.aliases
                        .insert(keyring_alias.to_string(), HashMap::new());
                }
                let aliases = self.aliases.get_mut(keyring_alias).unwrap();
                aliases.insert(key_alias.to_string(), key.id);
                if let Some(old_key) = self.keys.get(&key.id).cloned() {
                    self.update_derived_cache_for_key(&old_key, &key);
                } else {
                    self.derive_cache_key(&key);
                }
                T::KeyhouseExt::customer_key_metadata_refresh(&key);
                self.keys.insert(key.id, key);
            }
            StoreUpdateData::NewKeyring(keyring)
            | StoreUpdateData::CacheInvalidateKeyring(keyring) => {
                self.keyrings.insert(keyring.alias.clone(), keyring);
            }
            StoreUpdateData::UpdateIntermediateKey(intermediate_key)
            | StoreUpdateData::CacheInvalidateIntermediateKey(intermediate_key) => {
                self.intermediate_key = Some(intermediate_key);
            }
            StoreUpdateData::StoreSecret(secret)
            | StoreUpdateData::CacheInvalidateSecret(secret) => {
                let (key_alias, secret_alias) = split_last_alias(&secret.alias);
                if !self.secrets.contains_key(key_alias) {
                    self.secrets.insert(key_alias.to_string(), HashMap::new());
                }
                self.secrets
                    .get_mut(key_alias)
                    .unwrap()
                    .insert(secret_alias.to_string(), secret);
            }
            StoreUpdateData::DeleteSecret(alias) => {
                let (key_alias, secret_alias) = split_last_alias(&alias);
                if let Some(secrets) = self.secrets.get_mut(key_alias) {
                    secrets.remove(secret_alias);
                }
            }
        }
        Ok(())
    }

    fn add_derived_acl(
        &mut self,
        domain: AccessControlDomain,
        components: &BTreeMap<String, Option<String>>,
        id: u32,
    ) {
        for (component, value) in components {
            let total_component = (component.to_string(), value.clone());
            if !self.derived_acl_index.contains_key(&total_component) {
                self.derived_acl_index
                    .insert(total_component.clone(), BTreeMap::new());
            }
            let inverse_acls = self.derived_acl_index.get_mut(&total_component).unwrap();
            inverse_acls.entry(domain).or_insert_with(BTreeSet::new);
            let inverse_domain_acls = inverse_acls.get_mut(&domain).unwrap();
            inverse_domain_acls.insert(id);
        }
    }

    fn remove_derived_acl(
        &mut self,
        domain: AccessControlDomain,
        components: &BTreeMap<String, Option<String>>,
        id: u32,
    ) {
        for (component, value) in components {
            let total_component = (component.to_string(), value.clone());
            if !self.derived_acl_index.contains_key(&total_component) {
                return;
            }
            let inverse_acls = self.derived_acl_index.get_mut(&total_component).unwrap();
            if !inverse_acls.contains_key(&domain) {
                return;
            }
            let inverse_domain_acls = inverse_acls.get_mut(&domain).unwrap();
            inverse_domain_acls.remove(&id);
        }
    }

    fn derive_cache(&mut self) {
        self.derived_acl_index.clear();
        for (_, key) in self.keys.clone() {
            // cloning due to needing &mut self inside...
            self.derive_cache_key(&key);
        }
    }

    fn derive_cache_key(&mut self, key: &CustomerKey) {
        for (domain, acls) in &key.acls {
            for acl in acls {
                self.add_derived_acl(*domain, acl.get_components(), key.id);
            }
        }
    }

    fn update_derived_cache_for_key(&mut self, old_key: &CustomerKey, new_key: &CustomerKey) {
        if old_key.id != new_key.id {
            return;
        }
        let mut mutated = false;
        if old_key.acls != new_key.acls {
            mutated = true;
            for (domain, acls) in &old_key.acls {
                for acl in acls {
                    self.remove_derived_acl(*domain, acl.get_components(), old_key.id);
                }
            }
        }
        if mutated {
            self.derive_cache_key(new_key);
        }
    }
}

/// wraps another store and provide outwardly identical functionality
/// this is a writethrough cache with hard update constraints, requiring waiting up to `min_update_delay` ms to finish a write.
pub struct MemStore<T: KeyhouseImpl + 'static> {
    backing_store: OwnedStore<T>,
    instant: ArcSwap<MemStoreInstant>,
    max_update_delay: u64,
    min_update_delay: u64,
    pending_updates: mpsc::Sender<StoreUpdate>, // from the child store
    forward_updates: ArcSwap<Option<mpsc::Sender<StoreUpdate>>>, // used to forward updates to parent store from this and child
}

async fn reload_internal<T: KeyhouseImpl + 'static>(
    store: &OwnedStore<T>,
) -> Result<MemStoreInstant> {
    let (keys, aliases, keyrings, intermediate_key, secrets) = try_join!(
        store.get_all_customer_keys(),
        store.get_all_customer_key_aliases(),
        store.get_all_keyrings(),
        store.get_intermediate_key(),
        store.get_all_secrets(),
    )?;
    T::KeyhouseExt::emit_metric(Metric::CacheFullReload);

    let mut store = MemStoreInstant {
        keys,
        aliases,
        keyrings,
        intermediate_key,
        secrets,
        derived_acl_index: HashMap::new(),
    };
    store.derive_cache();

    Ok(store)
}

impl<T: KeyhouseImpl + 'static> MemStore<T> {
    #[allow(clippy::new_ret_no_self)]
    pub async fn new(
        backing_store: OwnedStore<T>,
        max_update_delay: u64,
        min_update_delay: u64,
    ) -> Result<OwnedStore<T>> {
        let (instant, receiver, sender);
        loop {
            match Self::init(&backing_store).await {
                Ok((new_instant, new_receiver, new_sender)) => {
                    instant = new_instant;
                    receiver = new_receiver;
                    sender = new_sender;
                    break;
                }
                Err(e) => {
                    error!("failed to load cache: {:?}, retrying in 1 second", e);
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }

        let store = Arc::new(MemStore {
            backing_store,
            instant,
            max_update_delay,
            min_update_delay,
            pending_updates: sender,
            forward_updates: ArcSwap::new(Arc::new(None)),
        });

        tokio::spawn(store.clone().update_thread(receiver));

        Ok(store)
    }

    async fn init(
        backing_store: &OwnedStore<T>,
    ) -> Result<(
        ArcSwap<MemStoreInstant>,
        mpsc::Receiver<StoreUpdate>,
        mpsc::Sender<StoreUpdate>,
    )> {
        let instant = ArcSwap::new(Arc::new(reload_internal(backing_store).await?));

        let (sender, receiver) = mpsc::channel::<StoreUpdate>(1024);
        backing_store.hook_updates(sender.clone()).await?;
        Ok((instant, receiver, sender))
    }

    /// copies the current instant and applies a set of updates, updates cache
    async fn partial_reload(self: Arc<MemStore<T>>, updates: Vec<StoreUpdate>) {
        let mut new_instant = (**self.instant.load()).clone();
        let forward_updates = self.forward_updates.load();
        let mut pending_dispatch: Vec<(Result<()>, oneshot::Sender<Result<()>>)> = vec![];
        for event in updates.into_iter() {
            if let Some(forward_updates) = forward_updates.as_ref() {
                forward_updates
                    .send(StoreUpdate {
                        data: event.data.clone(),
                        result: None,
                    })
                    .await
                    .ok();
            }
            let apply_result = new_instant.apply_update::<T>(event.data);

            if let Some(result) = event.result {
                if apply_result.is_err() {
                    result.send(apply_result).ok();
                } else {
                    pending_dispatch.push((apply_result, result));
                }
            }
        }
        T::KeyhouseExt::emit_metric(Metric::CachePartialReload);
        self.instant.swap(Arc::new(new_instant));
        for (apply_result, result) in pending_dispatch.into_iter() {
            if let Err(Err(e)) = result.send(apply_result) {
                warn!("dispath event error: {:?}", e);
            }
        }
    }

    /// manages reload delays and receiving events from child store
    async fn update_thread(self: Arc<MemStore<T>>, mut receiver: mpsc::Receiver<StoreUpdate>) {
        let mut queued_events: Vec<StoreUpdate> = vec![];
        // controls throttle for events into store
        let min_duration = Duration::from_millis(self.min_update_delay);
        // controls complete refresh of cache
        let max_duration = Duration::from_millis(
            self.max_update_delay + rand::random::<u64>() % (self.max_update_delay / 10 + 1),
        );
        let mut current_min_delay = Instant::now() + min_duration;
        let mut current_max_delay = Instant::now() + max_duration;
        loop {
            select!(
                event = receiver.recv().fuse() => {
                    if event.is_none() {
                        break;
                    }
                    T::KeyhouseExt::emit_metric(Metric::CacheUpdateReceived);
                    let event = event.unwrap();
                    queued_events.push(event);
                    if queued_events.len() == 1 {
                        current_min_delay = Instant::now() + min_duration;
                    }
                },
                _ = time::sleep_until(current_min_delay).fuse() => {
                    current_min_delay = Instant::now() + min_duration;
                    if !queued_events.is_empty() {
                        self.clone().partial_reload(queued_events).await;
                        queued_events = vec![];
                    }
                },
                _ = time::sleep_until(current_max_delay).fuse() => {
                    current_max_delay = Instant::now() + max_duration;
                    for event in queued_events.drain(..) {
                        if let Some(result) = event.result {
                            result.send(Ok(())).ok();
                        }
                    }
                    if let Err(e) = self.reload().await {
                        error!("error during regular reload, ignoring: {:?}", e);
                    }
                },
            )
        }
    }
}

#[tonic::async_trait]
impl<T: KeyhouseImpl + 'static> Store<T> for MemStore<T> {
    async fn reload(&self) -> Result<()> {
        self.instant
            .swap(Arc::new(reload_internal(&self.backing_store).await?));
        Ok(())
    }

    async fn get_customer_key_by_id(&self, id: u32) -> Result<Option<CustomerKey>> {
        let instant = self.instant.load();
        Ok(instant.keys.get(&id).cloned())
    }

    async fn get_customer_key_by_alias(&self, alias: &str) -> Result<Option<CustomerKey>> {
        let instant = self.instant.load();
        let (keyring_alias, key_alias) = split_alias(alias);
        let id = instant
            .aliases
            .get(&keyring_alias.to_string())
            .map(|x| x.get(key_alias))
            .flatten();
        if id.is_none() {
            return Ok(None);
        }
        let id = id.unwrap();

        Ok(instant.keys.get(id).cloned())
    }

    async fn mutate_customer_key(
        &self,
        id: u32,
        mutation: CustomerKeyMutation,
    ) -> Result<CustomerKey> {
        // unnecessary but improves latency in error case
        let instant = self.instant.load();
        if !instant.keys.contains_key(&id) {
            return Err(anyhow!("key '{}' does not exist to mutate", id));
        }
        drop(instant);
        self.backing_store
            .mutate_customer_key(id, mutation.clone())
            .await?;

        let (sender, receiver) = oneshot::channel::<Result<()>>();

        self.pending_updates
            .send(StoreUpdate {
                data: StoreUpdateData::KeyMutation { id, mutation },
                result: Some(sender),
            })
            .await
            .map_err(|_| anyhow!("failed up send update to cache"))?;

        receiver
            .await
            .unwrap_or_else(|e| Err(anyhow!("no response from cache: {:?}", e)))?;
        let instant = self.instant.load();
        instant
            .keys
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("key '{}' does not exist post mutation", id) as Error)
    }

    async fn reencode_customer_key(
        &self,
        id: u32,
        old_sensitives: Sensitives,
        new_sensitives: Sensitives,
        updated_at: Option<u64>,
    ) -> Result<CustomerKey> {
        // unnecessary but improves latency in error case
        let instant = self.instant.load();
        if !instant.keys.contains_key(&id) {
            return Err(anyhow!("key '{}' does not exist to reencode", id));
        }
        drop(instant);
        self.backing_store
            .reencode_customer_key(
                id,
                old_sensitives.clone(),
                new_sensitives.clone(),
                updated_at,
            )
            .await?;

        let (sender, receiver) = oneshot::channel::<Result<()>>();

        self.pending_updates
            .send(StoreUpdate {
                data: StoreUpdateData::KeyEncoded {
                    id,
                    sensitives: new_sensitives,
                },
                result: Some(sender),
            })
            .await
            .map_err(|_| anyhow!("failed up send update to cache"))?;

        receiver
            .await
            .unwrap_or_else(|e| Err(anyhow!("no response from cache: {:?}", e)))?;
        let instant = self.instant.load();
        instant
            .keys
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("key '{}' does not exist post reencoding", id) as Error)
    }

    async fn get_all_customer_keys_by_acl_component(
        &self,
        domain: Option<AccessControlDomain>,
        component_name: &str,
        component_value: Option<&str>,
    ) -> Result<Vec<CustomerKey>> {
        let total_component = (
            component_name.to_string(),
            component_value.map(|x| x.to_string()),
        );
        let instant = self.instant.load();
        let id_acl_map = match instant.derived_acl_index.get(&total_component) {
            Some(x) => x,
            None => return Ok(vec![]),
        };
        let ids: Vec<u32> = if let Some(domain) = domain {
            id_acl_map
                .get(&domain)
                .map(|x| x.iter().copied().collect())
                .unwrap_or_default()
        } else {
            let mut ids = vec![];
            for acls in id_acl_map.values() {
                ids.extend(acls.iter().copied());
            }
            ids.sort_unstable();
            ids.dedup();
            ids
        };
        Ok(ids
            .into_iter()
            .flat_map(|x| instant.keys.get(&x).cloned())
            .collect::<Vec<CustomerKey>>())
    }

    async fn get_all_customer_keys(&self) -> Result<HashMap<u32, CustomerKey>> {
        let instant = self.instant.load();
        Ok(instant.keys.clone())
    }

    async fn get_all_customer_key_aliases(&self) -> Result<HashMap<String, HashMap<String, u32>>> {
        let instant = self.instant.load();
        Ok(instant.aliases.clone())
    }

    async fn store_customer_key(&self, mut key: CustomerKey) -> Result<()> {
        // unnecessary but improves latency in error case
        let instant = self.instant.load();
        if instant.keys.contains_key(&key.id) {
            return Err(anyhow!("keys cannot be overriden"));
        }

        self.backing_store.store_customer_key(key.clone()).await?;

        let (sender, receiver) = oneshot::channel::<Result<()>>();
        key.init_runtime::<T>().await?;

        self.pending_updates
            .send(StoreUpdate {
                data: StoreUpdateData::NewKey(key),
                result: Some(sender),
            })
            .await
            .map_err(|_| anyhow!("failed up send update to cache"))?;

        receiver
            .await
            .unwrap_or_else(|e| Err(anyhow!("no response from cache: {:?}", e)))
    }

    async fn store_keyring(&self, keyring: Keyring) -> Result<()> {
        let instant = self.instant.load();
        if instant.keyrings.contains_key(&keyring.alias) {
            return Err(anyhow!("keyrings cannot be overriden"));
        }

        self.backing_store.store_keyring(keyring.clone()).await?;

        let (sender, receiver) = oneshot::channel::<Result<()>>();

        self.pending_updates
            .send(StoreUpdate {
                data: StoreUpdateData::NewKeyring(keyring),
                result: Some(sender),
            })
            .await
            .map_err(|_| anyhow!("failed up send update to cache"))?;

        receiver
            .await
            .unwrap_or_else(|e| Err(anyhow!("no response from cache: {:?}", e)))
    }

    async fn get_keyring(&self, alias: &str) -> Result<Option<Keyring>> {
        let instant = self.instant.load();
        Ok(instant.keyrings.get(alias).cloned())
    }

    async fn get_keyring_keys(&self, alias: &str) -> Result<Vec<CustomerKey>> {
        let instant = self.instant.load();
        let aliases = if let Some(aliases) = instant.aliases.get(alias) {
            aliases
        } else {
            return Ok(vec![]);
        };
        Ok(aliases
            .iter()
            .flat_map(|(_, id)| instant.keys.get(id).cloned())
            .collect())
    }

    async fn get_all_keyrings(&self) -> Result<HashMap<String, Keyring>> {
        let instant = self.instant.load();
        Ok(instant.keyrings.clone())
    }

    async fn get_intermediate_key(&self) -> Result<Option<IntermediateKey>> {
        let instant = self.instant.load();
        Ok(instant.intermediate_key.clone())
    }

    async fn set_intermediate_key(
        &self,
        old_key: Option<IntermediateKey>,
        new_key: IntermediateKey,
    ) -> Result<()> {
        self.backing_store
            .set_intermediate_key(old_key, new_key.clone())
            .await?;

        let (sender, receiver) = oneshot::channel::<Result<()>>();

        self.pending_updates
            .send(StoreUpdate {
                data: StoreUpdateData::UpdateIntermediateKey(new_key),
                result: Some(sender),
            })
            .await
            .map_err(|_| anyhow!("failed up send update to cache"))?;

        receiver
            .await
            .unwrap_or_else(|e| Err(anyhow!("no response from cache: {:?}", e)))
    }

    async fn get_secret(&self, alias: &str) -> Result<Option<Secret>> {
        let (key_alias, secret_alias) = split_last_alias(alias);
        let instant = self.instant.load();
        Ok(instant
            .secrets
            .get(key_alias)
            .map(|x| x.get(secret_alias).cloned())
            .flatten())
    }

    async fn delete_secret(&self, alias: &str) -> Result<bool> {
        if !self.backing_store.delete_secret(alias).await? {
            return Ok(false);
        }

        let (sender, receiver) = oneshot::channel::<Result<()>>();

        self.pending_updates
            .send(StoreUpdate {
                data: StoreUpdateData::DeleteSecret(alias.to_string()),
                result: Some(sender),
            })
            .await
            .map_err(|_| anyhow!("failed up send update to cache"))?;

        receiver
            .await
            .unwrap_or_else(|e| Err(anyhow!("no response from cache: {:?}", e)))?;
        Ok(true)
    }

    async fn get_key_secrets(&self, alias: &str) -> Result<Vec<Secret>> {
        let instant = self.instant.load();
        Ok(instant
            .secrets
            .get(alias)
            .map(|x| {
                x.iter()
                    .map(|(_, secret)| secret.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(Vec::new))
    }

    async fn count_key_secrets(&self, alias: &str) -> Result<usize> {
        let instant = self.instant.load();
        Ok(instant
            .secrets
            .get(alias)
            .map(|x| x.len())
            .unwrap_or_default())
    }

    async fn store_secret(&self, previous_secret: Option<Secret>, secret: Secret) -> Result<()> {
        if let Some(previous_secret) = &previous_secret {
            if previous_secret.alias != secret.alias {
                return Err(anyhow!(
                    "store_secret alias of previous_secret and secret didn't match"
                ));
            }
        }

        self.backing_store
            .store_secret(previous_secret, secret.clone())
            .await?;

        let (sender, receiver) = oneshot::channel::<Result<()>>();

        self.pending_updates
            .send(StoreUpdate {
                data: StoreUpdateData::StoreSecret(secret),
                result: Some(sender),
            })
            .await
            .map_err(|_| anyhow!("failed up send update to cache"))?;

        receiver
            .await
            .unwrap_or_else(|e| Err(anyhow!("no response from cache: {:?}", e)))
    }

    async fn get_all_secrets(&self) -> Result<HashMap<String, HashMap<String, Secret>>> {
        let instant = self.instant.load();
        Ok(instant.secrets.clone())
    }

    /// this will flood updates during cache refresh cycles
    /// WARNING: all hard reloads will drop all pending updates. this function is inherently lossy
    async fn hook_updates(&self, sender: mpsc::Sender<StoreUpdate>) -> Result<()> {
        self.forward_updates.swap(Arc::new(Some(sender)));
        Ok(())
    }

    async fn cache_invalidation(
        &self,
        invalidation: &CacheInvalidation,
    ) -> Result<Option<StoreUpdateData>> {
        let invalidation = self.backing_store.cache_invalidation(invalidation).await?;
        if let Some(invalidation) = invalidation {
            let (sender, receiver) = oneshot::channel::<Result<()>>();

            self.pending_updates
                .send(StoreUpdate {
                    data: invalidation,
                    result: Some(sender),
                })
                .await
                .map_err(|_| anyhow!("failed up send update to cache"))?;

            receiver
                .await
                .unwrap_or_else(|e| Err(anyhow!("no response from cache: {:?}", e)))?;
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    async fn cache_store(prefix: &str) -> OwnedStore<()> {
        assert!(prefix.ends_with("/"));
        let config = crate::server_suite::config::SERVER_CONFIG.get();
        let etcd_address = &config.0.etcd_addresses[0];
        let under_store = EtcdStore::<()>::new(
            prefix.to_string(),
            vec![etcd_address.clone()],
            config.1.etcd_client_tls_config(),
            None,
        )
        .await
        .unwrap();
        under_store.clear_store().await.unwrap();

        let store = MemStore::<()>::new(Arc::new(under_store), 60000, 100)
            .await
            .unwrap();
        store
    }

    #[tokio::test]
    async fn cache_roundtrip() -> Result<()> {
        let store = cache_store("cache_roundtrip/").await;
        let mut key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        key.acls.insert(
            AccessControlDomain::GetSecret,
            vec![
                SpiffeIDMatcher::new("spiffe://test/ns:test/id:mytestpsm".parse().unwrap())
                    .unwrap(),
            ],
        );

        let id = key.id;
        assert_eq!(store.get_customer_key_by_id(id).await?, None);
        store.store_customer_key(key.clone()).await?;

        assert_eq!(store.get_customer_key_by_id(id).await?, Some(key.clone()));
        assert_eq!(
            store.get_customer_key_by_alias(&key.alias).await?,
            Some(key.clone())
        );

        let acl_keys = store
            .get_all_customer_keys_by_acl_component(
                Some(AccessControlDomain::GetSecret),
                "id",
                Some("mytestpsm"),
            )
            .await?;
        assert_eq!(acl_keys.len(), 1);
        assert_eq!(&acl_keys[0], &key);

        let keys = store.get_all_customer_keys().await?;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys.get(&key.id), Some(&key));
        let aliases = store.get_all_customer_key_aliases().await?;
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases.get("test").unwrap().len(), 1);
        assert_eq!(
            aliases.get("test").map(|x| x.get("test")).flatten(),
            Some(&key.id)
        );

        Ok(())
    }

    #[tokio::test]
    async fn cache_update_status() -> Result<()> {
        let store = cache_store("cache_update_status/").await;
        let mut key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        let id = key.id;
        store.store_customer_key(key.clone()).await?;
        store
            .mutate_customer_key(
                id,
                CustomerKeyMutation {
                    status: Some(KeyStatus::Disabled),
                    description: Some("test2".to_string()),
                    ..Default::default()
                },
            )
            .await?;
        key.description = "test2".to_string();
        assert_eq!(store.get_customer_key_by_id(id).await?, Some(key.clone()));

        Ok(())
    }

    #[tokio::test]
    async fn cache_update_acl() -> Result<()> {
        let store = cache_store("cache_update_acl/").await;
        let mut key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        let id = key.id;

        let matcher =
            SpiffeIDMatcher::new("spiffe://test/ns:test/id:mytestpsm".parse().unwrap()).unwrap();

        store.store_customer_key(key.clone()).await?;
        assert_eq!(
            store
                .get_all_customer_keys_by_acl_component(
                    Some(AccessControlDomain::GetSecret),
                    "id",
                    Some("mytestpsm")
                )
                .await
                .unwrap(),
            vec![]
        );

        store
            .mutate_customer_key(
                id,
                CustomerKeyMutation {
                    acls: {
                        let mut acls = BTreeMap::new();
                        acls.insert(AccessControlDomain::GetSecret, vec![matcher.clone()]);
                        Some(acls)
                    },
                    ..Default::default()
                },
            )
            .await?;
        key.acls
            .insert(AccessControlDomain::GetSecret, vec![matcher.clone()]);
        assert_eq!(store.get_customer_key_by_id(id).await?, Some(key.clone()));

        assert_eq!(
            store
                .get_all_customer_keys_by_acl_component(
                    Some(AccessControlDomain::GetSecret),
                    "id",
                    Some("mytestpsm")
                )
                .await
                .unwrap(),
            vec![key.clone()]
        );
        assert_eq!(
            store
                .get_all_customer_keys_by_acl_component(None, "id", Some("mytestpsm"))
                .await
                .unwrap(),
            vec![key.clone()]
        );

        store
            .mutate_customer_key(
                id,
                CustomerKeyMutation {
                    acls: Some(BTreeMap::new()),
                    ..Default::default()
                },
            )
            .await?;
        key.acls.clear();
        assert_eq!(store.get_customer_key_by_id(id).await?, Some(key.clone()));

        assert_eq!(
            store
                .get_all_customer_keys_by_acl_component(
                    Some(AccessControlDomain::GetSecret),
                    "id",
                    Some("mytestpsm")
                )
                .await
                .unwrap(),
            vec![]
        );
        Ok(())
    }

    #[tokio::test]
    async fn cache_static_alias() -> Result<()> {
        let store = cache_store("cache_static_alias/").await;
        let key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        let key2 = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        store.store_customer_key(key.clone()).await?;
        store
            .store_customer_key(key2.clone())
            .await
            .expect_err("did not fail");
        Ok(())
    }

    #[tokio::test]
    async fn cache_watcher() -> Result<()> {
        let store = cache_store("cache_watcher/").await;
        let (sender, mut receiver) = mpsc::channel::<StoreUpdate>(1024);
        store.hook_updates(sender).await?;
        // make sure etcd is listening for events
        sleep(Duration::from_millis(1000)).await;

        let key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        let id = key.id;
        store.store_customer_key(key.clone()).await.unwrap();
        store
            .mutate_customer_key(
                id,
                CustomerKeyMutation {
                    status: Some(KeyStatus::Disabled),
                    description: Some("new description".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let mut new_key = key.clone();
        new_key.description = "new description".to_string();
        assert_eq!(
            store.get_customer_key_by_id(id).await.unwrap(),
            Some(new_key.clone())
        );

        let mut results: Vec<usize> = vec![];
        for _ in 0..4usize {
            let event = receiver.recv().await.unwrap().data;
            match event {
                StoreUpdateData::NewKey(new_key) => {
                    results.push(0);
                    assert_eq!(new_key, key);
                }
                StoreUpdateData::KeyMutation { id, mutation } => {
                    results.push(1);
                    assert_eq!(id, key.id);
                    assert_eq!(mutation.status.unwrap(), KeyStatus::Disabled);
                }
                StoreUpdateData::CacheInvalidate(cache_key) => {
                    if cache_key == key {
                        results.push(2);
                    } else if cache_key == new_key {
                        results.push(3);
                    } else {
                        // could also need to be key, this is for the error message
                        assert_eq!(cache_key, new_key);
                    }
                }
                _ => (),
            }
        }
        results.sort();
        assert_eq!(results, vec![0, 1, 2, 3]);
        Ok(())
    }

    #[tokio::test]
    async fn cache_watcher_keyring() -> Result<()> {
        let store = cache_store("cache_watcher_keyring/").await;
        let (sender, mut receiver) = mpsc::channel::<StoreUpdate>(1024);

        let key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        store.store_customer_key(key.clone()).await?;
        store.hook_updates(sender).await?;
        // make sure etcd is listening for events
        sleep(Duration::from_millis(1000)).await;

        let keyring = Keyring::new_base("test".to_string());
        store.store_keyring(keyring.clone()).await?;
        let new_keyring = store.get_keyring(&keyring.alias).await?.unwrap();
        assert_eq!(keyring, new_keyring);

        let mut results: Vec<usize> = vec![];
        for _ in 0..2usize {
            let event = receiver.recv().await.unwrap().data;
            match event {
                StoreUpdateData::NewKeyring(new_keyring) => {
                    results.push(0);
                    assert_eq!(&new_keyring, &keyring);
                }
                StoreUpdateData::CacheInvalidateKeyring(cache_keyring) => {
                    if cache_keyring == keyring {
                        results.push(1);
                    } else {
                        // could also need to be keyring, this is for the error message
                        assert_eq!(cache_keyring, keyring);
                    }
                }
                _ => (),
            }
        }
        results.sort();
        assert_eq!(results, vec![0, 1]);
        Ok(())
    }

    #[tokio::test]
    async fn cache_keyring_roundtrip() -> Result<()> {
        let store = cache_store("cache_keyring_roundtrip/").await;
        let key1 = CustomerKey::new_base::<()>("test/test1".to_string()).unwrap();
        store.store_customer_key(key1.clone()).await.unwrap();
        let keyring = Keyring::new_base("test".to_string());
        assert_eq!(store.get_keyring(&keyring.alias).await.unwrap(), None);
        store.store_keyring(keyring.clone()).await.unwrap();
        assert_eq!(
            store.get_keyring(&keyring.alias).await.unwrap(),
            Some(keyring.clone())
        );

        assert_eq!(
            store.get_keyring(&keyring.alias).await.unwrap(),
            Some(keyring.clone())
        );
        assert_eq!(
            store.get_keyring_keys(&keyring.alias).await.unwrap(),
            vec![key1.clone()]
        );

        let key2 = CustomerKey::new_base::<()>("test/test2".to_string()).unwrap();
        store.store_customer_key(key2.clone()).await.unwrap();

        let keyring = store.get_keyring(&keyring.alias).await.unwrap().unwrap();
        let mut cache_keys = store.get_keyring_keys(&keyring.alias).await.unwrap();
        cache_keys.sort_by(|a, b| a.alias.cmp(&b.alias));
        assert_eq!(cache_keys, vec![key1.clone(), key2.clone()]);
        assert_eq!(
            store
                .get_all_keyrings()
                .await
                .unwrap()
                .values()
                .collect::<Vec<&Keyring>>(),
            vec![&keyring]
        );

        Ok(())
    }

    #[tokio::test]
    async fn cache_intermediate_key_roundtrip() {
        use crate::server_suite::store::intermediate_key;
        let store = cache_store("cache_intermediate_key_roundtrip/").await;
        assert_eq!(store.get_intermediate_key().await.unwrap(), None);
        let new_key = intermediate_key::IntermediateKey::reset(store.clone())
            .await
            .unwrap();
        assert_eq!(
            store.get_intermediate_key().await.unwrap().unwrap(),
            new_key
        );
    }

    #[tokio::test]
    async fn cache_intermediate_key_check() {
        use crate::server_suite::store::intermediate_key;
        let store = cache_store("cache_intermediate_key_check/").await;
        let mut new_key = intermediate_key::IntermediateKey::reset(store.clone())
            .await
            .unwrap();
        new_key.decoded = None;
        let mut customer_key = CustomerKey::new_base::<()>("test".to_string()).unwrap();
        customer_key.sensitives.as_mut().unwrap().intermediate_key = new_key.clone();
        store
            .store_customer_key(customer_key.clone())
            .await
            .unwrap();
        assert!(store
            .get_customer_key_by_id(customer_key.id)
            .await
            .unwrap()
            .unwrap()
            .sensitives
            .unwrap()
            .intermediate_key
            .decoded
            .is_some(),);
    }

    #[tokio::test]
    async fn cache_secret_roundtrip() {
        let store = cache_store("cache_secret_roundtrip/").await;
        let keyring = Keyring::new_base("test_ring".to_string());
        store.store_keyring(keyring.clone()).await.unwrap();
        let key = CustomerKey::new_base::<()>("test_ring/test_key".to_string()).unwrap();
        store.store_customer_key(key.clone()).await.unwrap();

        assert_eq!(store.get_all_secrets().await.unwrap(), HashMap::new());
        assert_eq!(
            store.get_key_secrets("test_ring/test_key").await.unwrap(),
            vec![]
        );
        assert_eq!(
            store
                .get_secret("test_ring/test_key/test_secret")
                .await
                .unwrap(),
            None
        );

        let secret = Secret::new_base("test_ring/test_key/test_secret".to_string());
        store.store_secret(None, secret.clone()).await.unwrap();

        assert_eq!(
            store
                .get_all_secrets()
                .await
                .unwrap()
                .get("test_ring/test_key")
                .unwrap()
                .get("test_secret")
                .unwrap(),
            &secret
        );
        assert_eq!(
            store.get_key_secrets("test_ring/test_key").await.unwrap(),
            vec![secret.clone()]
        );
        assert_eq!(
            store
                .get_secret("test_ring/test_key/test_secret")
                .await
                .unwrap(),
            Some(secret.clone())
        );
        store
            .store_secret(None, secret.clone())
            .await
            .expect_err("failed to prevent invalid transaction");

        let new_secret = Secret::new_base("test_ring/test_key/test_secret".to_string());
        store
            .store_secret(Some(new_secret.clone()), secret.clone())
            .await
            .expect_err("failed to prevent invalid transaction");
        store
            .store_secret(Some(secret.clone()), new_secret.clone())
            .await
            .unwrap();
        assert_eq!(
            store
                .get_all_secrets()
                .await
                .unwrap()
                .get("test_ring/test_key")
                .unwrap()
                .get("test_secret")
                .unwrap(),
            &new_secret
        );
        assert_eq!(
            store.get_key_secrets("test_ring/test_key").await.unwrap(),
            vec![new_secret.clone()]
        );
        assert_eq!(
            store
                .get_secret("test_ring/test_key/test_secret")
                .await
                .unwrap(),
            Some(new_secret.clone())
        );

        let secret2 = Secret::new_base("test_ring/test_key/test_secret2".to_string());
        store.store_secret(None, secret2.clone()).await.unwrap();
        assert_eq!(
            store
                .get_all_secrets()
                .await
                .unwrap()
                .get("test_ring/test_key")
                .unwrap()
                .get("test_secret")
                .unwrap(),
            &new_secret
        );
        assert_eq!(
            store
                .get_all_secrets()
                .await
                .unwrap()
                .get("test_ring/test_key")
                .unwrap()
                .get("test_secret2")
                .unwrap(),
            &secret2
        );
        let mut etcd_secrets = store.get_key_secrets("test_ring/test_key").await.unwrap();
        etcd_secrets.sort_by(|a, b| a.alias.cmp(&b.alias));
        let mut expected_secrets = vec![new_secret.clone(), secret2.clone()];
        expected_secrets.sort_by(|a, b| a.alias.cmp(&b.alias));
        assert_eq!(etcd_secrets, expected_secrets);
        assert_eq!(
            store
                .get_secret("test_ring/test_key/test_secret")
                .await
                .unwrap(),
            Some(new_secret.clone())
        );
        assert_eq!(
            store
                .get_secret("test_ring/test_key/test_secret2")
                .await
                .unwrap(),
            Some(secret2.clone())
        );
        assert_eq!(
            true,
            store
                .delete_secret("test_ring/test_key/test_secret2")
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .get_secret("test_ring/test_key/test_secret2")
                .await
                .unwrap(),
            None
        );
    }
}
