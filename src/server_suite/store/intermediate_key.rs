#[allow(unused_imports)]
use crate::master_key::MasterKeyProvider;
use crate::server_suite::coding::CodingItem;
use crate::server_suite::config::SERVER_CONFIG;
use crate::server_suite::store::{CustomerKey, KeyVec, LegacyDataKey, OwnedStore, Sensitives};
use crate::util;
use crate::KeyhouseImpl;
use crate::{prelude::*, Metric};
use arc_swap::ArcSwap;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Clone, Debug, Eq)]
pub struct IntermediateKey {
    pub id: Uuid,
    #[serde(
        serialize_with = "util::vec_as_base64",
        deserialize_with = "util::vec_from_base64"
    )]
    pub item: Vec<u8>,
    pub created_at: u64,
    pub master_key_id: String,
    #[serde(skip)]
    pub decoded: Option<Arc<IntermediateKeyDecoded>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, Eq, PartialEq)]
#[zeroize(drop)]
pub struct IntermediateKeyDecoded(pub(crate) Vec<u8>);

pub async fn customer_key_recoder<T: KeyhouseImpl + 'static>(store: OwnedStore<T>) {
    loop {
        sleep(Duration::from_secs(3600)).await;
        if crate::SERVER_CONFIG.get().0.read_only {
            continue;
        }
        let all_keys = match store.get_all_customer_key_aliases().await {
            Ok(x) => x,
            Err(e) => {
                error!("error loading all keys for recode: {:?}", e);
                continue;
            }
        };
        match IntermediateKey::reload_checked(store.clone()).await {
            Ok(_) => (),
            Err(e) => {
                error!("error reloading and fetching intermediate key: {:?}", e);
                continue;
            }
        };

        let throttle_qps = crate::SERVER_CONFIG
            .get()
            .0
            .customer_key_rotation_throttle_qps;
        let delay_us = if throttle_qps == 0 {
            0u64
        } else {
            1000000 / throttle_qps
        };

        let mut all_keys = all_keys
            .into_iter()
            .flat_map(|x| x.1.into_iter().map(|x| x.1))
            .collect::<Vec<u32>>();

        let mut rng = StdRng::from_entropy();
        all_keys.shuffle(&mut rng);

        for key_id in all_keys {
            match customer_key_recode_key(&store, key_id).await {
                Err(e) => {
                    error!(
                        "failed to update customer key '{}' during recode: {:?}",
                        key_id, e
                    );
                    continue;
                }
                Ok(true) => {
                    if delay_us != 0 {
                        tokio::time::sleep(Duration::from_micros(delay_us)).await;
                    }
                }
                Ok(false) => (),
            }
        }
    }
}

// true if recoding happened
async fn customer_key_recode_key<T: KeyhouseImpl + 'static>(
    store: &OwnedStore<T>,
    key_id: u32,
) -> Result<bool> {
    let key = store.get_customer_key_by_id(key_id).await?;
    if key.is_none() {
        warn!(
            "key id {} disappeared or could not be resolved before recoding happened, skipped",
            key_id
        );
        return Ok(false);
    }
    let key = key.unwrap();

    // refetch in case more than rotation is ongoing and we have a strict throttle
    let intermediate_key = IntermediateKey::reload_checked(store.clone()).await?;
    if key.sensitives.as_ref().unwrap().intermediate_key != intermediate_key {
        intermediate_key.customer_key_recode(store, key).await?;
        return Ok(true);
    }
    Ok(false)
}

impl PartialEq for IntermediateKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

lazy_static! {
    // this will thrash on occasion but will settle quickly due to very infrequent writes
    pub static ref INTERMEDIATE_KEY_CACHE: ArcSwap<HashMap<Uuid, Arc<IntermediateKeyDecoded>>> = ArcSwap::new(Arc::new(HashMap::new()));
}

impl IntermediateKey {
    pub(crate) async fn decode<T: KeyhouseImpl + 'static>(&mut self) -> Result<()> {
        let cache = INTERMEDIATE_KEY_CACHE.load();
        if let Some(cached) = cache.get(&self.id) {
            self.decoded = Some(cached.clone());
            return Ok(());
        }
        let decoded = Arc::new(IntermediateKeyDecoded(
            T::MasterKeyProvider::decode(&self.master_key_id, self.item.clone()).await?,
        ));
        let mut new_cache = (**cache).clone();
        new_cache.insert(self.id, decoded.clone());
        INTERMEDIATE_KEY_CACHE.swap(Arc::new(new_cache));
        self.decoded = Some(decoded);
        Ok(())
    }

    pub(crate) async fn generate<T: KeyhouseImpl + 'static>() -> Result<IntermediateKey> {
        let master_key_id = &SERVER_CONFIG.get().0.master_key_id;
        let mut intermediate_key = IntermediateKey {
            id: Uuid::new_v4(),
            item: T::MasterKeyProvider::encode(
                master_key_id,
                T::IntermediateItem::generate().encode_self()?,
            )
            .await?,
            created_at: util::epoch(),
            master_key_id: master_key_id.to_string(),
            decoded: None,
        };
        intermediate_key.decode::<T>().await?;
        Ok(intermediate_key)
    }

    pub fn encode_customer_key<T: KeyhouseImpl + 'static>(&self, key: Vec<u8>) -> Result<Vec<u8>> {
        match &self.decoded {
            Some(decoded) => Ok(T::IntermediateItem::decode_self(&*decoded.0)?.encode_data(key)?),
            None => Err(anyhow!("intermediate key isnt decoded")),
        }
    }

    pub fn decode_customer_key<T: KeyhouseImpl + 'static>(&self, key: Vec<u8>) -> Result<Vec<u8>> {
        match &self.decoded {
            Some(decoded) => Ok(T::IntermediateItem::decode_self(&*decoded.0)?.decode_data(key)?),
            None => Err(anyhow!("intermediate key isnt decoded")),
        }
    }

    pub async fn reset<T: KeyhouseImpl + 'static>(store: OwnedStore<T>) -> Result<Self> {
        let new_key = IntermediateKey::generate::<T>().await?;
        store
            .set_intermediate_key(store.get_intermediate_key().await?, new_key.clone())
            .await?;
        Ok(new_key)
    }

    pub async fn reload_checked<T: KeyhouseImpl + 'static>(store: OwnedStore<T>) -> Result<Self> {
        use crate::event::*;
        let source_intermediate_key = store.get_intermediate_key().await?;
        if source_intermediate_key.is_none() {
            return IntermediateKey::reset(store).await;
        }
        let source_intermediate_key = source_intermediate_key.unwrap();
        let master_key_id = &SERVER_CONFIG.get().0.master_key_id;
        let cycle_time = SERVER_CONFIG.get().0.intermediate_key_rotation_seconds;
        if cycle_time > 0
            && (source_intermediate_key.created_at + cycle_time * 1000 < util::epoch()
                || &*source_intermediate_key.master_key_id != master_key_id)
        {
            let new_key = IntermediateKey::generate::<T>().await?;
            // if we fail to store, we should try again next cycle (most likely an update conflict)
            if store
                .set_intermediate_key(Some(source_intermediate_key.clone()), new_key.clone())
                .await
                .is_ok()
            {
                LogEvent::InternalLogEvent(InternalLogEvent {
                    occurred_at: crate::util::epoch(),
                    request_type: InternalRequestType::ReissueIntermediateKey,
                    key_id: None,
                    key_alias: None,
                    success: true,
                    message: None,
                })
                .fire::<T>();
                T::KeyhouseExt::emit_metric(Metric::IntermediateKeyReissued);
                return Ok(new_key);
            }
        }

        store
            .get_intermediate_key()
            .await
            .transpose()
            .unwrap_or_else(|| Err(anyhow!("intermediate key not found after set")))
    }

    async fn customer_key_recode<T: KeyhouseImpl + 'static>(
        &self,
        store: &OwnedStore<T>,
        key: CustomerKey,
    ) -> Result<()> {
        let sensitives = key
            .sensitives
            .as_ref()
            .ok_or_else(|| anyhow!("no sensitives on customer key"))?;

        let mut encoded_keys = vec![];
        for key in &sensitives.keys {
            let decoded_key = sensitives
                .intermediate_key
                .decode_customer_key::<T>(key.0.clone())?;
            encoded_keys.push(KeyVec(self.encode_customer_key::<T>(decoded_key)?));
        }
        let encoded_legacy_key = LegacyDataKey {
            data_key: self.encode_customer_key::<T>(
                sensitives
                    .intermediate_key
                    .decode_customer_key::<T>(sensitives.legacy_key.data_key.clone())?,
            )?,
        };
        let encoded_seed = self.encode_customer_key::<T>(
            sensitives
                .intermediate_key
                .decode_customer_key::<T>(sensitives.seed.0.clone())?,
        )?;

        store
            .reencode_customer_key(
                key.id,
                key.sensitives.unwrap(),
                Sensitives {
                    seed: KeyVec(encoded_seed),
                    keys: encoded_keys,
                    intermediate_key: self.clone(),
                    legacy_key: encoded_legacy_key,
                },
                None,
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn intermediate_bootstrap() {
        let store: OwnedStore<()> = Arc::new(MockStore::new().await.unwrap());
        IntermediateKey::reload_checked(store.clone())
            .await
            .unwrap();

        let key = store.get_intermediate_key().await.unwrap();
        assert!(key.is_some());
    }

    #[tokio::test]
    async fn intermediate_expiration_reissue() {
        let store: OwnedStore<()> = Arc::new(MockStore::new().await.unwrap());
        IntermediateKey::reload_checked(store.clone())
            .await
            .unwrap();

        let old_key = store.get_intermediate_key().await.unwrap().unwrap();
        let mut key = old_key.clone();
        let cycle_time = SERVER_CONFIG.get().0.intermediate_key_rotation_seconds;
        key.created_at = util::epoch() - cycle_time * 1000 - 100;
        store
            .set_intermediate_key(Some(old_key.clone()), key.clone())
            .await
            .unwrap();

        IntermediateKey::reload_checked(store.clone())
            .await
            .unwrap();

        let new_key = store.get_intermediate_key().await.unwrap().unwrap();
        assert_ne!(new_key, key);
        assert_ne!(new_key, old_key);
    }

    #[tokio::test]
    async fn intermediate_current() {
        let store: OwnedStore<()> = Arc::new(MockStore::new().await.unwrap());
        IntermediateKey::reload_checked(store.clone())
            .await
            .unwrap();
        let key1 = store.get_intermediate_key().await.unwrap().unwrap();
        IntermediateKey::reload_checked(store.clone())
            .await
            .unwrap();

        let key2 = store.get_intermediate_key().await.unwrap().unwrap();
        assert_eq!(key1, key2);
    }

    #[tokio::test]
    async fn intermediate_recode_key() {
        let store: OwnedStore<()> = Arc::new(MockStore::new().await.unwrap());
        IntermediateKey::reload_checked(store.clone())
            .await
            .unwrap();
        let key1 = store.get_intermediate_key().await.unwrap().unwrap();
        let customer_key = CustomerKey::new_base::<()>("test".to_string()).unwrap();
        store
            .store_customer_key(customer_key.clone())
            .await
            .unwrap();
        key1.customer_key_recode(&store, customer_key.clone())
            .await
            .unwrap();

        IntermediateKey::reload_checked(store.clone())
            .await
            .unwrap();

        let key2 = store.get_intermediate_key().await.unwrap().unwrap();
        assert_eq!(key1, key2);
    }

    #[tokio::test]
    async fn intermediate_round_trip_customer_key() {
        let key = IntermediateKey::generate::<()>().await.unwrap();
        let test_payload: Vec<u8> = vec![5; 32];
        let encoded = key.encode_customer_key::<()>(test_payload.clone()).unwrap();
        let decoded = key.decode_customer_key::<()>(encoded.clone()).unwrap();
        assert_eq!(test_payload, decoded);
    }
}
