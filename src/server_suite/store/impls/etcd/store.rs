use super::*;
use crate::{util::time::epoch_us, Metric};
use std::future::Future;
use std::sync::atomic::Ordering;

pub(super) async fn etcd_wrap<
    E: KeyhouseImpl + 'static,
    T,
    F: Future<Output = etcd_rs::Result<T>>,
>(
    method: &'static str,
    fut: F,
) -> Result<T> {
    let start = epoch_us();
    let result = fut.await;
    let stop = epoch_us();
    E::KeyhouseExt::emit_metric(Metric::EtcdOperation {
        latency: (stop - start) as f64 / 1000.0,
        success: result.is_ok(),
        method,
    });
    if result.is_ok() {
        crate::control::ETCD_LAST_CONTACT.store(crate::util::epoch(), Ordering::Relaxed);
    }

    result.map_err(|e| anyhow!("{:?}", e))
}

impl<T: KeyhouseImpl + 'static> EtcdStore<T> {
    async fn get_raw_key(&self, key: String) -> Result<Option<String>> {
        let request = RangeRequest::new(KeyRange::key(key));
        let mut response =
            etcd_wrap::<T, _, _>("get_raw_key", self.client.kv().range(request)).await?;
        let all_keys = response.take_kvs();
        assert!(all_keys.len() < 2);
        let raw_key = all_keys
            .into_iter()
            .next()
            .map(|mut kv| String::from_utf8(kv.take_value()))
            .transpose()?;

        Ok(raw_key)
    }

    async fn get_customer_key_by_id_internal(
        &self,
        id: u32,
    ) -> Result<Option<(CustomerKey, String)>> {
        let raw_key = self
            .get_raw_key(format!("{}keys/{}", self.prefix, id))
            .await?;

        if raw_key.is_none() {
            return Ok(None);
        }
        let raw_key = raw_key.unwrap();

        let mut key: CustomerKey = serde_json::from_str(&raw_key)?;
        key.init_runtime::<T>().await?;

        Ok(Some((key, raw_key)))
    }
}

#[tonic::async_trait]
impl<T: KeyhouseImpl + 'static> Store<T> for EtcdStore<T> {
    async fn reload(&self) -> Result<()> {
        Ok(())
    }

    async fn get_customer_key_by_id(&self, id: u32) -> Result<Option<CustomerKey>> {
        match self.get_customer_key_by_id_internal(id).await? {
            None => Ok(None),
            Some((key, _)) => Ok(Some(key)),
        }
    }

    // another option here is to pull all by prefix and filter if we want the latest version -- but we would end up pulling a lot of data in some cases
    async fn get_customer_key_by_alias(&self, alias: &str) -> Result<Option<CustomerKey>> {
        let raw_id = self
            .get_raw_key(format!("{}key_aliases/{}", self.prefix, alias))
            .await?;

        if raw_id.is_none() {
            return Ok(None);
        }

        self.get_customer_key_by_id(raw_id.unwrap().parse()?).await
    }

    async fn mutate_customer_key(
        &self,
        id: u32,
        mutation: CustomerKeyMutation,
    ) -> Result<CustomerKey> {
        let (current_key, current_key_raw) = match self.get_customer_key_by_id_internal(id).await? {
            Some(x) => x,
            None => {
                return Err(anyhow!("key not found"));
            }
        };

        let mut new_key = current_key.clone();
        new_key.apply_mutation(mutation);

        let key_id = format!("{}keys/{}", self.prefix, id);
        let response = etcd_wrap::<T, _, _>(
            "mutate_customer_key",
            self.client.kv().txn(
                TxnRequest::new()
                    .when_value(KeyRange::key(&*key_id), TxnCmp::Equal, current_key_raw)
                    .and_then(PutRequest::new(key_id, serde_json::to_string(&new_key)?)),
            ),
        )
        .await?;

        if !response.is_success() {
            Err(anyhow!("update in progress"))
        } else {
            Ok(new_key)
        }
    }

    async fn reencode_customer_key(
        &self,
        id: u32,
        old_sensitives: Sensitives,
        new_sensitives: Sensitives,
        updated_at: Option<u64>,
    ) -> Result<CustomerKey> {
        let (current_key, current_key_raw) = match self.get_customer_key_by_id_internal(id).await? {
            Some(x) => x,
            None => {
                return Err(anyhow!("key not found"));
            }
        };
        if current_key.sensitives.as_ref().unwrap() != &old_sensitives {
            return Err(anyhow!("stale key update"));
        }

        let mut new_customer_key = current_key.clone();
        new_customer_key.sensitives = Some(new_sensitives);
        if let Some(updated_at) = updated_at {
            new_customer_key.updated_at = updated_at;
        }

        let key_id = format!("{}keys/{}", self.prefix, id);
        let response = etcd_wrap::<T, _, _>(
            "reencode_customer_key",
            self.client.kv().txn(
                TxnRequest::new()
                    .when_value(KeyRange::key(&*key_id), TxnCmp::Equal, current_key_raw)
                    .and_then(PutRequest::new(
                        key_id,
                        serde_json::to_string(&new_customer_key)?,
                    )),
            ),
        )
        .await?;
        if !response.is_success() {
            Err(anyhow!("update in progress"))
        } else {
            Ok(new_customer_key)
        }
    }

    async fn get_all_customer_keys_by_acl_component(
        &self,
        _domain: Option<AccessControlDomain>,
        _component_name: &str,
        _component_value: Option<&str>,
    ) -> Result<Vec<CustomerKey>> {
        Err(anyhow!(
            "get_all_customer_keys_by_acl_component is not implemented in etcd store"
        ))
    }

    async fn get_all_customer_keys(&self) -> Result<HashMap<u32, CustomerKey>> {
        let request = RangeRequest::new(KeyRange::prefix(format!("{}keys/", self.prefix)));
        let mut response =
            etcd_wrap::<T, _, _>("get_all_customer_keys", self.client.kv().range(request)).await?;
        let mut map = response
            .take_kvs()
            .iter()
            .filter_map(|kv| {
                let key: StdResult<CustomerKey, _> = serde_json::from_str(kv.value_str());
                match key {
                    Err(e) => {
                        sentry_error!(
                            "could not parse customer key, id: '{}', error: {:?}",
                            kv.key_str(),
                            e
                        );
                        None
                    }
                    Ok(key) => Some((key.id, key)),
                }
            })
            .collect::<HashMap<u32, CustomerKey>>();
        for (_, key) in map.iter_mut() {
            key.init_runtime::<T>().await?;
        }
        Ok(map)
    }

    async fn get_all_customer_key_aliases(&self) -> Result<HashMap<String, HashMap<String, u32>>> {
        let prefix = format!("{}key_aliases/", self.prefix);
        let request = RangeRequest::new(KeyRange::prefix(&*prefix));
        let mut response = etcd_wrap::<T, _, _>(
            "get_all_customer_key_aliases",
            self.client.kv().range(request),
        )
        .await?;
        let mut output = HashMap::new();

        for kv in response.take_kvs().into_iter() {
            let alias = &kv.key_str()[prefix.len()..];
            let (keyring_alias, key_alias) = split_alias(alias);
            let id: u32 = match kv.value_str().parse() {
                Err(e) => {
                    sentry_error!(
                        "could not parse id in alias, alias: '{}', error: {:?}",
                        alias,
                        e
                    );
                    continue;
                }
                Ok(id) => id,
            };
            if !output.contains_key(keyring_alias) {
                output.insert(keyring_alias.to_string(), HashMap::new());
            }
            output
                .get_mut(keyring_alias)
                .unwrap()
                .insert(key_alias.to_string(), id);
        }
        Ok(output)
    }

    async fn store_customer_key(&self, key: CustomerKey) -> Result<()> {
        let id = format!("{}keys/{}", self.prefix, key.id);
        let alias_key = format!("{}key_aliases/{}", self.prefix, &key.alias);
        let request = TxnRequest::new()
            .when_create_revision(KeyRange::key(id.clone()), TxnCmp::Equal, 0)
            .when_create_revision(KeyRange::key(alias_key.clone()), TxnCmp::Equal, 0)
            .and_then(PutRequest::new(
                id.to_string(),
                serde_json::to_string(&key)?,
            ))
            .and_then(PutRequest::new(alias_key, key.id.to_string()));
        let response =
            etcd_wrap::<T, _, _>("store_customer_key", self.client.kv().txn(request)).await?;
        if !response.is_success() {
            return Err(anyhow!("keys cannot be overriden"));
        }
        // putresponse has no error case here
        Ok(())
    }

    async fn store_keyring(&self, keyring: Keyring) -> Result<()> {
        let id = format!("{}keyrings/{}", self.prefix, keyring.alias);
        let request = TxnRequest::new()
            .when_create_revision(KeyRange::key(&*id), TxnCmp::Equal, 0)
            .and_then(PutRequest::new(
                id.to_string(),
                serde_json::to_string(&keyring)?,
            ));
        let response = etcd_wrap::<T, _, _>("store_keyring", self.client.kv().txn(request)).await?;
        if !response.is_success() {
            return Err(anyhow!("keyrings cannot be overriden"));
        }
        // putresponse has no error case here
        Ok(())
    }

    async fn get_keyring(&self, alias: &str) -> Result<Option<Keyring>> {
        let request = RangeRequest::new(KeyRange::key(format!(
            "{}keyrings/{}",
            self.prefix,
            alias.to_string()
        )));
        let mut response =
            etcd_wrap::<T, _, _>("get_keyring", self.client.kv().range(request)).await?;
        let all_keys = response.take_kvs();
        assert!(all_keys.len() < 2);
        let raw_keyring = all_keys.first().map(|kv| kv.value_str());
        if raw_keyring.is_none() {
            return Ok(None);
        }
        Ok(serde_json::from_str(raw_keyring.unwrap())?)
    }

    async fn get_keyring_keys(&self, alias: &str) -> Result<Vec<CustomerKey>> {
        let request = RangeRequest::new(KeyRange::prefix(format!(
            "{}key_aliases/{}/",
            self.prefix, alias
        )));
        let mut response =
            etcd_wrap::<T, _, _>("get_keyring_keys", self.client.kv().range(request)).await?;
        let ids = response
            .take_kvs()
            .iter()
            .filter_map(|kv| {
                let id: StdResult<u32, _> = kv.value_str().parse();
                match id {
                    Err(e) => {
                        sentry_error!(
                            "could not parse customer key id, id: '{}', error: {:?}",
                            kv.key_str(),
                            e
                        );
                        None
                    }
                    Ok(id) => Some(id),
                }
            })
            .collect::<Vec<u32>>();
        let mut output = Vec::with_capacity(ids.len());
        for id in ids {
            match self.get_customer_key_by_id(id).await {
                Err(e) => {
                    sentry_error!("could not parse customer key, id: '{}', error: {:?}", id, e);
                }
                Ok(Some(key)) => {
                    output.push(key);
                }
                _ => (),
            }
        }
        Ok(output)
    }

    async fn get_all_keyrings(&self) -> Result<HashMap<String, Keyring>> {
        let request = RangeRequest::new(KeyRange::prefix(format!("{}keyrings/", self.prefix)));
        let mut response =
            etcd_wrap::<T, _, _>("get_all_keyrings", self.client.kv().range(request)).await?;
        Ok(response
            .take_kvs()
            .iter()
            .filter_map(|kv| {
                let key: StdResult<Keyring, _> = serde_json::from_str(kv.value_str());
                match key {
                    Err(e) => {
                        sentry_error!(
                            "could not parse keyring, id: '{}', error: {:?}",
                            kv.key_str(),
                            e
                        );
                        None
                    }
                    Ok(key) => Some((key.alias.clone(), key)),
                }
            })
            .collect::<HashMap<String, Keyring>>())
    }

    async fn get_intermediate_key(&self) -> Result<Option<IntermediateKey>> {
        debug!("enter get_intermediate_key. constructing rangerequest.");
        let request = RangeRequest::new(KeyRange::key(format!("{}intermediate_key", self.prefix)));
        debug!("rangerequest prepared. waiting for response ...");
        let mut response =
            etcd_wrap::<T, _, _>("get_intermediate_key", self.client.kv().range(request)).await?;
        debug!("response received. parsing ...");
        let all_keys = response.take_kvs();
        assert!(all_keys.len() < 2);
        let raw_key = all_keys.first().map(|kv| kv.value_str());
        let mut key: Option<IntermediateKey> =
            raw_key.map(|key| serde_json::from_str(key)).transpose()?;
        debug!("parse complete! trying to decode intermediate_key");
        if let Some(key) = &mut key {
            key.decode::<T>().await?;
        }
        debug!("decode complete!");
        Ok(key)
    }

    async fn set_intermediate_key(
        &self,
        old_key: Option<IntermediateKey>,
        new_key: IntermediateKey,
    ) -> Result<()> {
        let key_id = format!("{}intermediate_key", self.prefix);
        let mut req = TxnRequest::new();
        req = if let Some(old_key) = old_key {
            req.when_value(
                KeyRange::key(&*key_id),
                TxnCmp::Equal,
                &*serde_json::to_string(&old_key)?,
            )
        } else {
            req.when_create_revision(KeyRange::key(&*key_id), TxnCmp::Equal, 0)
        };

        let response = etcd_wrap::<T, _, _>(
            "set_intermediate_key",
            self.client
                .kv()
                .txn(req.and_then(PutRequest::new(key_id, &*serde_json::to_string(&new_key)?))),
        )
        .await?;
        if !response.is_success() {
            Err(anyhow!("update in progress"))
        } else {
            Ok(())
        }
    }

    async fn get_secret(&self, alias: &str) -> Result<Option<Secret>> {
        let request = RangeRequest::new(KeyRange::key(format!("{}secrets/{}", self.prefix, alias)));
        let mut response =
            etcd_wrap::<T, _, _>("get_secret", self.client.kv().range(request)).await?;
        let all_keys = response.take_kvs();
        assert!(all_keys.len() < 2);
        let raw_secret = all_keys.first().map(|kv| kv.value_str());
        if raw_secret.is_none() {
            return Ok(None);
        }

        let secret: Secret = serde_json::from_str(raw_secret.unwrap())?;
        Ok(Some(secret))
    }

    async fn delete_secret(&self, alias: &str) -> Result<bool> {
        let request =
            DeleteRequest::new(KeyRange::key(format!("{}secrets/{}", self.prefix, alias)));
        let response =
            etcd_wrap::<T, _, _>("delete_secret", self.client.kv().delete(request)).await?;
        if response.count_deleted() > 0 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn get_key_secrets(&self, alias: &str) -> Result<Vec<Secret>> {
        let request = RangeRequest::new(KeyRange::prefix(format!(
            "{}secrets/{}/",
            self.prefix, alias
        )));
        let mut response =
            etcd_wrap::<T, _, _>("get_key_secrets", self.client.kv().range(request)).await?;
        let mut output = vec![];
        for value in response.take_kvs().into_iter() {
            output.push(serde_json::from_slice(value.value())?);
        }
        Ok(output)
    }

    async fn count_key_secrets(&self, alias: &str) -> Result<usize> {
        let request = RangeRequest::new(KeyRange::prefix(format!(
            "{}secrets/{}/",
            self.prefix, alias
        )));
        let mut response =
            etcd_wrap::<T, _, _>("count_key_secrets", self.client.kv().range(request)).await?;
        Ok(response.take_kvs().len())
    }

    async fn store_secret(&self, previous_secret: Option<Secret>, secret: Secret) -> Result<()> {
        if let Some(previous_secret) = &previous_secret {
            if previous_secret.alias != secret.alias {
                return Err(anyhow!(
                    "store_secret alias of previous_secret and secret didn't match"
                ));
            }
        }

        let request = RangeRequest::new(KeyRange::key(format!(
            "{}secrets/{}",
            self.prefix, secret.alias
        )));
        let mut response =
            etcd_wrap::<T, _, _>("store_secret_get", self.client.kv().range(request)).await?;
        let all_keys = response.take_kvs();
        assert!(all_keys.len() < 2);
        let raw_old_secret = all_keys.first().map(|kv| kv.value_str());
        let old_secret: Option<Secret> = raw_old_secret.map(serde_json::from_str).transpose()?;

        if old_secret != previous_secret {
            return Err(anyhow!("attempted store with stale previous secret"));
        }
        let secret_json = serde_json::to_string(&secret)?;

        let id = format!("{}secrets/{}", self.prefix, &secret.alias);
        let mut request = TxnRequest::new();
        request = match raw_old_secret {
            Some(secret) => request.when_value(KeyRange::key(&*id), TxnCmp::Equal, secret),
            None => request.when_create_revision(KeyRange::key(&*id), TxnCmp::Equal, 0),
        };
        request = request.and_then(PutRequest::new(id.to_string(), secret_json));
        let response =
            etcd_wrap::<T, _, _>("store_secret_set", self.client.kv().txn(request)).await?;
        if !response.is_success() {
            return Err(anyhow!("store secret transaction failed"));
        }
        Ok(())
    }

    async fn get_all_secrets(&self) -> Result<HashMap<String, HashMap<String, Secret>>> {
        let request = RangeRequest::new(KeyRange::prefix(format!("{}secrets/", self.prefix,)));
        let mut response =
            etcd_wrap::<T, _, _>("get_all_secrets", self.client.kv().range(request)).await?;
        let mut output = HashMap::new();
        for value in response.take_kvs().into_iter() {
            let secret: Secret = match serde_json::from_slice(value.value()) {
                Err(e) => {
                    sentry_error!(
                        "could not parse secret, id: '{}', error: {:?}",
                        value.key_str(),
                        e
                    );
                    continue;
                }
                Ok(secret) => secret,
            };
            let (key_alias, secret_alias) = split_last_alias(&secret.alias);
            if !output.contains_key(key_alias) {
                output.insert(key_alias.to_string(), HashMap::new());
            }
            output
                .get_mut(key_alias)
                .unwrap()
                .insert(secret_alias.to_string(), secret);
        }
        Ok(output)
    }

    async fn hook_updates(&self, sender: mpsc::Sender<StoreUpdate>) -> Result<()> {
        use watch::*;
        tokio::spawn(<EtcdStoreWatcher as StoreWatcher<CustomerKey, T>>::watch(
            &EtcdStoreWatcher,
            self.internal_duplicate_connection().await?,
            sender.clone(),
        ));
        tokio::spawn(<EtcdStoreWatcher as StoreWatcher<Keyring, T>>::watch(
            &EtcdStoreWatcher,
            self.internal_duplicate_connection().await?,
            sender.clone(),
        ));
        tokio::spawn(
            <EtcdStoreWatcher as StoreWatcher<IntermediateKey, T>>::watch(
                &EtcdStoreWatcher,
                self.internal_duplicate_connection().await?,
                sender.clone(),
            ),
        );
        tokio::spawn(<EtcdStoreWatcher as StoreWatcher<Secret, T>>::watch(
            &EtcdStoreWatcher,
            self.internal_duplicate_connection().await?,
            sender,
        ));
        Ok(())
    }

    async fn cache_invalidation(
        &self,
        invalidation: &CacheInvalidation,
    ) -> Result<Option<StoreUpdateData>> {
        Ok(Some(match invalidation {
            CacheInvalidation::Key { id } => {
                if let Some(key) = self.get_customer_key_by_id(*id).await? {
                    StoreUpdateData::CacheInvalidate(key)
                } else {
                    return Ok(None);
                }
            }
            CacheInvalidation::Keyring { alias } => {
                if let Some(key) = self.get_keyring(&**alias).await? {
                    StoreUpdateData::CacheInvalidateKeyring(key)
                } else {
                    return Ok(None);
                }
            }
            CacheInvalidation::IntermediateKey => {
                if let Some(key) = self.get_intermediate_key().await? {
                    StoreUpdateData::CacheInvalidateIntermediateKey(key)
                } else {
                    return Ok(None);
                }
            }
            CacheInvalidation::Secret { alias } => match self.get_secret(&**alias).await? {
                Some(secret) => StoreUpdateData::CacheInvalidateSecret(secret),
                None => StoreUpdateData::DeleteSecret(alias.clone()),
            },
        }))
    }
}
