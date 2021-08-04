use super::*;
use crate::prelude::*;
use chashmap::CHashMap;
use std::marker::PhantomData;
use tokio::sync::RwLock;

pub struct MockStore<T: KeyhouseImpl + 'static> {
    pub keys: CHashMap<u32, CustomerKey>,
    pub aliases: CHashMap<String, HashMap<String, u32>>,
    pub keyrings: CHashMap<String, Keyring>,
    pub secrets: CHashMap<String, HashMap<String, Secret>>,
    pub intermediate_key: RwLock<Option<IntermediateKey>>,
    _phantom: PhantomData<T>,
}

impl<T: KeyhouseImpl + 'static> MockStore<T> {
    pub async fn new() -> Result<Self> {
        Ok(MockStore {
            keys: CHashMap::new(),
            aliases: CHashMap::new(),
            keyrings: CHashMap::new(),
            secrets: CHashMap::new(),
            intermediate_key: RwLock::new(None),
            _phantom: PhantomData::<T>,
        })
    }
}

#[tonic::async_trait]
impl<T: KeyhouseImpl + 'static> Store<T> for MockStore<T> {
    async fn reload(&self) -> Result<()> {
        Ok(())
    }

    #[allow(clippy::map_clone)]
    async fn get_customer_key_by_id(&self, id: u32) -> Result<Option<CustomerKey>> {
        Ok(self.keys.get(&id).map(|x| x.clone()))
    }

    #[allow(clippy::map_clone)]
    async fn get_customer_key_by_alias(&self, alias: &str) -> Result<Option<CustomerKey>> {
        let (keyring_alias, key_alias) = split_alias(alias);
        let id = self.aliases.get(&keyring_alias.to_string());
        if id.is_none() {
            return Ok(None);
        }
        let id = id.unwrap();
        let id = id.get(key_alias);
        if id.is_none() {
            return Ok(None);
        }
        let id = id.unwrap();

        Ok(self.keys.get(id).map(|x| x.clone()))
    }

    async fn mutate_customer_key(
        &self,
        id: u32,
        mutation: CustomerKeyMutation,
    ) -> Result<CustomerKey> {
        let mut new_key = None::<CustomerKey>;
        self.keys.alter(id, |existing| match existing {
            Some(mut key) => {
                if let Some(description) = mutation.description {
                    key.description = description;
                }
                if let Some(acls) = mutation.acls {
                    key.acls = acls;
                }
                if let Some(status) = mutation.status {
                    key.status = status;
                }
                new_key = Some(key.clone());
                Some(key)
            }
            None => None,
        });
        new_key.ok_or_else(|| anyhow!("mutate_customer_key: key '{}' not found", id) as Error)
    }

    async fn reencode_customer_key(
        &self,
        id: u32,
        old_sensitives: Sensitives,
        new_sensitives: Sensitives,
        updated_at: Option<u64>,
    ) -> Result<CustomerKey> {
        let mut new_customer_key = None::<CustomerKey>;
        self.keys.alter(id, |existing| match existing {
            Some(mut key) => {
                if key.sensitives.as_ref().unwrap() != &old_sensitives {
                    new_customer_key = None;
                    return Some(key);
                }
                key.sensitives = Some(new_sensitives);
                if let Some(updated_at) = updated_at {
                    key.updated_at = updated_at;
                }
                new_customer_key = Some(key.clone());
                Some(key)
            }
            None => None,
        });
        new_customer_key
            .ok_or_else(|| anyhow!("reencode_customer_key: key '{}' not found", id) as Error)
    }

    async fn get_all_customer_keys_by_acl_component(
        &self,
        domain: Option<AccessControlDomain>,
        component_name: &str,
        component_value: Option<&str>,
    ) -> Result<Vec<CustomerKey>> {
        Ok(self
            .keys
            .clone()
            .into_iter()
            .map(|(_, key)| key)
            .filter(|key| {
                if let Some(domain) = &domain {
                    if let Some(acl) = key.acls.get(domain) {
                        for matcher in acl {
                            if matcher.get_component(component_name).flatten() == component_value {
                                return true;
                            }
                        }
                    }
                } else {
                    for (_, acl) in key.acls.iter() {
                        for matcher in acl {
                            if matcher.get_component(component_name).flatten() == component_value {
                                return true;
                            }
                        }
                    }
                }

                false
            })
            .collect())
    }

    async fn get_all_customer_keys(&self) -> Result<HashMap<u32, CustomerKey>> {
        Ok(self.keys.clone().into_iter().collect())
    }

    async fn get_all_customer_key_aliases(&self) -> Result<HashMap<String, HashMap<String, u32>>> {
        Ok(self.aliases.clone().into_iter().collect())
    }

    async fn store_customer_key(&self, key: CustomerKey) -> Result<()> {
        let mut has_previous_key = true;
        // we are about to move the key, so grab what we need for later
        let alias = key.alias.clone();
        let id = key.id;

        // avoids a race condition
        self.keys.alter(key.id, |existing| match existing {
            Some(k) => Some(k),
            None => {
                has_previous_key = false;
                Some(key)
            }
        });
        if has_previous_key {
            return Err(anyhow!("keys cannot be overriden"));
        }
        let (keyring_alias, key_alias) = split_alias(&alias);

        self.aliases.alter(keyring_alias.to_string(), |entry| {
            let mut entry = entry.unwrap_or_else(HashMap::new);
            entry.insert(key_alias.to_string(), id);
            Some(entry)
        });

        Ok(())
    }

    async fn store_keyring(&self, keyring: Keyring) -> Result<()> {
        let mut has_previous_keyring = true;
        // we are about to move the keyring, so grab what we need for later
        let alias = keyring.alias.clone();

        // avoids a race condition
        self.keyrings.alter(alias, |existing| match existing {
            Some(k) => Some(k),
            None => {
                has_previous_keyring = false;
                Some(keyring)
            }
        });
        if has_previous_keyring {
            return Err(anyhow!("keyrings cannot be overriden"));
        }
        Ok(())
    }

    #[allow(clippy::map_clone)]
    async fn get_keyring(&self, alias: &str) -> Result<Option<Keyring>> {
        Ok(self.keyrings.get(alias).map(|x| x.clone()))
    }

    async fn get_keyring_keys(&self, alias: &str) -> Result<Vec<CustomerKey>> {
        let mut output = vec![];
        if let Some(aliases) = self.aliases.get(alias) {
            for (_, id) in (&*aliases).clone().into_iter() {
                if let Some(key) = self.keys.get(&id) {
                    output.push(key.clone());
                }
            }
        }
        Ok(output)
    }

    async fn get_all_keyrings(&self) -> Result<HashMap<String, Keyring>> {
        Ok(self.keyrings.clone().into_iter().collect())
    }

    async fn get_intermediate_key(&self) -> Result<Option<IntermediateKey>> {
        Ok(self.intermediate_key.read().await.clone())
    }

    async fn set_intermediate_key(
        &self,
        old_key: Option<IntermediateKey>,
        mut new_key: IntermediateKey,
    ) -> Result<()> {
        new_key.decode::<T>().await?;
        let mut current_key = self.intermediate_key.write().await;
        if *current_key != old_key {
            return Err(anyhow!("update in progress"));
        }
        *current_key = Some(new_key);
        Ok(())
    }

    async fn get_secret(&self, alias: &str) -> Result<Option<Secret>> {
        let (key_alias, secret_alias) = split_last_alias(alias);
        Ok(self
            .secrets
            .get(key_alias)
            .map(|x| x.get(secret_alias).cloned())
            .flatten())
    }

    async fn delete_secret(&self, alias: &str) -> Result<bool> {
        let (key_alias, secret_alias) = split_last_alias(alias);
        Ok(self
            .secrets
            .get_mut(key_alias)
            .map(|mut x| x.remove(secret_alias).map(|_| ()))
            .flatten()
            .is_some())
    }

    async fn get_key_secrets(&self, alias: &str) -> Result<Vec<Secret>> {
        Ok(self
            .secrets
            .get(alias)
            .map(|x| x.iter().map(|(_, secret)| secret).cloned().collect())
            .unwrap_or_else(Vec::new))
    }

    async fn count_key_secrets(&self, alias: &str) -> Result<usize> {
        Ok(self.secrets.get(alias).map(|x| x.len()).unwrap_or(0))
    }

    async fn store_secret(&self, previous_secret: Option<Secret>, secret: Secret) -> Result<()> {
        if let Some(previous_secret) = &previous_secret {
            assert_eq!(previous_secret.alias, secret.alias);
        }
        let (key_alias, secret_alias) = split_last_alias(&secret.alias);
        let key_alias = key_alias.to_string();
        let secret_alias = secret_alias.to_string();

        let mut previous_matched = false;
        self.secrets.alter(key_alias, |map| {
            let mut map = match map {
                None => HashMap::new(),
                Some(x) => x,
            };
            if map.get(&secret_alias) == previous_secret.as_ref() {
                previous_matched = true;
                map.insert(secret_alias, secret);
            }
            Some(map)
        });

        if !previous_matched {
            Err(anyhow!("previous_secret did not match"))
        } else {
            Ok(())
        }
    }

    async fn get_all_secrets(&self) -> Result<HashMap<String, HashMap<String, Secret>>> {
        Ok(self.secrets.clone().into_iter().collect())
    }

    async fn hook_updates(&self, _sender: mpsc::Sender<StoreUpdate>) -> Result<()> {
        Ok(())
    }

    async fn cache_invalidation(
        &self,
        _invalidation: &CacheInvalidation,
    ) -> Result<Option<StoreUpdateData>> {
        Ok(None)
    }
}
