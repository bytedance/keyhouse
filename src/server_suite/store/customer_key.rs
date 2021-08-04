use super::*;
use crate::customer_key::DataKey;
use crate::intermediate_key::IntermediateKeyDecoded;
use crate::server_suite::coding::CodingItem;
use crate::KeyhouseImpl;
use crate::{baseclient::ClientCoding, Metric};
use prost::Message;
use tokio::time::{sleep, Duration};
use zeroize::Zeroize;

pub async fn customer_key_reloader<T: KeyhouseImpl + 'static>(store: OwnedStore<T>) {
    loop {
        sleep(Duration::from_secs(3600)).await;
        if crate::SERVER_CONFIG.get().0.read_only {
            continue;
        }
        let all_keys = match store.get_all_customer_keys().await {
            Ok(x) => x,
            Err(e) => {
                error!("error loading all keys for reload check: {:?}", e);
                continue;
            }
        };

        for (_, key) in all_keys {
            if let Err(e) = key.reload_checked(&store).await {
                error!("error reloading customer key: {:?}", e);
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
pub enum KeyPurpose {
    EncodeDecode,
    SignVerify,
    Secret,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
pub enum KeyStatus {
    Enabled,
    Disabled,
}

pub type AccessControlList = Vec<SpiffeIDMatcher>;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessControlDomain {
    Encode,
    Decode,
    Sign,
    Verify,
    GetSecret,
    StoreSecret,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct LegacyDataKey {
    #[serde(
        serialize_with = "util::vec_as_base64",
        deserialize_with = "util::vec_from_base64"
    )]
    pub data_key: Vec<u8>,
}

impl LegacyDataKey {
    pub fn from_string<T: KeyhouseImpl + 'static>(
        intermediate_key: &IntermediateKey,
        data: String,
    ) -> Result<LegacyDataKey> {
        Ok(LegacyDataKey {
            data_key: intermediate_key.encode_customer_key::<T>(data.into_bytes())?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct KeyVec(
    #[serde(
        serialize_with = "util::vec_as_base64",
        deserialize_with = "util::vec_from_base64"
    )]
    pub Vec<u8>,
);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Sensitives {
    pub seed: KeyVec,
    pub keys: Vec<KeyVec>,
    pub legacy_key: LegacyDataKey,
    pub intermediate_key: IntermediateKey,
}

impl Zeroize for Sensitives {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.keys.zeroize();
        self.legacy_key.zeroize();
        // intermediate key is an Arc of IntermediateKeyDecoded.
        // IntermediateKeyDecoded derived Zeroize
    }
}

impl Drop for Sensitives {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl Sensitives {
    pub fn generate<T: KeyhouseImpl + 'static>(intermediate_key: &IntermediateKey) -> Result<Self> {
        let legacy_key = T::ClientCoding::generate().into_source();

        Sensitives::generate_legacy::<T>(intermediate_key, legacy_key)
    }

    pub fn generate_legacy<T: KeyhouseImpl + 'static>(
        intermediate_key: &IntermediateKey,
        legacy_key: Vec<u8>,
    ) -> Result<Self> {
        Ok(Sensitives {
            seed: KeyVec(
                intermediate_key.encode_customer_key::<T>(T::ClientCoding::generate_seed())?,
            ),
            keys: vec![KeyVec(intermediate_key.encode_customer_key::<T>(
                T::CustomerItem::generate().encode_self()?,
            )?)],
            legacy_key: LegacyDataKey {
                data_key: intermediate_key.encode_customer_key::<T>(legacy_key)?,
            },
            intermediate_key: intermediate_key.clone(),
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CustomerKey {
    pub id: u32,
    pub alias: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub description: String,
    pub purpose: KeyPurpose,
    pub acls: BTreeMap<AccessControlDomain, AccessControlList>,
    pub status: KeyStatus,
    pub sensitives: Option<Sensitives>,
    pub user_authorization_data: Vec<String>, // list of usernames
}

pub type DecodedDataKey = DataKey;

impl CustomerKey {
    pub fn new_base<T: KeyhouseImpl + 'static>(alias: String) -> Result<CustomerKey> {
        let intermediate_key = IntermediateKey {
            id: Uuid::new_v4(),
            item: vec![],
            created_at: util::epoch(),
            master_key_id: "".to_string(),
            decoded: Some(Arc::new(IntermediateKeyDecoded(
                T::IntermediateItem::generate().encode_self()?,
            ))),
        };

        Ok(CustomerKey {
            id: rand::random(),
            alias,
            created_at: util::epoch(),
            updated_at: util::epoch(),
            description: "".to_string(),
            purpose: KeyPurpose::EncodeDecode,
            acls: BTreeMap::new(),
            status: KeyStatus::Enabled,
            sensitives: Some(Sensitives::generate::<T>(&intermediate_key)?),
            user_authorization_data: vec![],
        })
    }

    // used for control plane backwards compatibility
    pub fn migrate_user_authorization_data(mut self) -> Self {
        let mut user_authorization_data = vec![];
        for acls in self.acls.values() {
            for acl in acls {
                if acl
                    .get_component("ns")
                    .flatten()
                    .map(|x| x == "user")
                    .unwrap_or(false)
                {
                    if let Some(user) = acl.get_component("id").flatten() {
                        user_authorization_data.push(user.to_string());
                    }
                }
            }
        }
        user_authorization_data.sort();
        user_authorization_data.dedup();
        self.user_authorization_data = user_authorization_data;
        self
    }

    pub async fn init_runtime<T: KeyhouseImpl + 'static>(&mut self) -> Result<()> {
        if let Some(sensitives) = self.sensitives.as_mut() {
            sensitives.intermediate_key.decode::<T>().await?;
        }
        if !self.user_authorization_data.is_empty() {
            for authorized_user in self.user_authorization_data.iter() {
                let svid = SpiffeIDMatcher::new(
                    format!("spiffe://user/ns:user/id:{}", authorized_user).parse()?,
                )?;
                let acls = self
                    .acls
                    .entry(AccessControlDomain::Encode)
                    .or_insert_with(Vec::new);
                if !acls.iter().any(|x| x == &svid) {
                    acls.push(svid.clone());
                }
                let acls = self
                    .acls
                    .entry(AccessControlDomain::Decode)
                    .or_insert_with(Vec::new);
                if !acls.iter().any(|x| x == &svid) {
                    acls.push(svid);
                }
            }
            self.user_authorization_data = vec![];
        }
        Ok(())
    }

    pub fn censor(mut self) -> Self {
        self.sensitives = None;
        self
    }

    pub(crate) fn apply_mutation(&mut self, mutation: CustomerKeyMutation) {
        if let Some(description) = mutation.description {
            self.description = description;
        }
        if let Some(acls) = mutation.acls {
            self.acls = acls;
        }
        if let Some(user_authorization_data) = mutation.user_authorization_data {
            self.user_authorization_data = user_authorization_data;
        }
    }

    pub fn generate_data_key<T: KeyhouseImpl + 'static>(&self) -> Result<T::ClientCoding> {
        let old_sensitives = self
            .sensitives
            .as_ref()
            .ok_or_else(|| anyhow!("no sensitives found for customer key"))?;
        let seed = old_sensitives
            .intermediate_key
            .decode_customer_key::<T>(old_sensitives.seed.0.clone())?;
        let epoch = crate::util::epoch() / (1000 * 60 * 60 * 24); // one per day
        Ok(T::ClientCoding::generate_epoch(seed, epoch))
    }

    pub fn encode_data_key<T: KeyhouseImpl + 'static>(&self) -> Result<(T::ClientCoding, Vec<u8>)> {
        let raw_key = self.generate_data_key::<T>()?;
        let key_id = self.id;
        let key_out = self
            .decode_key::<T>(None)?
            .encode_data(raw_key.into_source())?;
        let formed = DataKey {
            key: key_out,
            key_id,
            key_version: (self.sensitives.as_ref().unwrap().keys.len() - 1) as u32,
            timestamp: util::epoch_minutes(),
        };
        let mut formed_out = vec![];
        formed
            .encode(&mut formed_out)
            .expect("insufficient buffer space for encode");

        Ok((raw_key, formed_out))
    }

    pub fn pre_decode_data_key(encoded_key: &[u8]) -> Result<(u32, DecodedDataKey)> {
        let key = DataKey::decode(encoded_key)?;
        Ok((key.key_id, key))
    }

    pub fn decode_data_key<T: KeyhouseImpl + 'static>(
        &self,
        decoded: DecodedDataKey,
    ) -> Result<Vec<u8>> {
        let key_out = self
            .decode_key::<T>(Some(decoded.key_version as usize))?
            .decode_data(decoded.key)?;

        Ok(key_out)
    }

    pub async fn reload_checked<T: KeyhouseImpl + 'static>(
        self,
        store: &OwnedStore<T>,
    ) -> Result<Option<CustomerKey>> {
        let cycle_time = crate::SERVER_CONFIG.get().0.customer_key_rotation_seconds;
        if cycle_time == 0
            || self.status == KeyStatus::Enabled
                && self.updated_at + cycle_time * 1000 > util::epoch()
        {
            return Ok(None);
        }
        T::KeyhouseExt::emit_metric(Metric::CustomerKeyReissued);
        Ok(Some(self.reload(store).await?))
    }

    pub async fn reload<T: KeyhouseImpl + 'static>(
        self,
        store: &OwnedStore<T>,
    ) -> Result<CustomerKey> {
        use crate::event::*;
        let old_sensitives = self
            .sensitives
            .ok_or_else(|| anyhow!("no sensitives found for customer key"))?;
        let mut new_sensitives = old_sensitives.clone();
        new_sensitives.keys.push(KeyVec(
            old_sensitives
                .intermediate_key
                .encode_customer_key::<T>(T::CustomerItem::generate().encode_self()?)?,
        ));
        T::KeyhouseExt::emit_metric(Metric::CustomerKeyReencoded);

        let customer_key = store
            .reencode_customer_key(
                self.id,
                old_sensitives,
                new_sensitives,
                Some(crate::util::epoch()),
            )
            .await;

        LogEvent::InternalLogEvent(InternalLogEvent {
            occurred_at: crate::util::epoch(),
            request_type: InternalRequestType::ReissueCustomerKey,
            key_id: Some(self.id),
            key_alias: Some(self.alias.clone()),
            success: customer_key.is_ok(),
            message: customer_key.as_ref().err().map(|e| format!("{:?}", e)),
        })
        .fire::<T>();

        Ok(customer_key?)
    }

    pub fn decode_key<T: KeyhouseImpl + 'static>(
        &self,
        id: Option<usize>,
    ) -> Result<T::CustomerItem> {
        let sensitives = self
            .sensitives
            .as_ref()
            .ok_or_else(|| anyhow!("no sensitives on customer key"))?;
        let key = if let Some(id) = id {
            sensitives.keys.get(id)
        } else {
            sensitives.keys.last()
        };
        if key.is_none() {
            return Err(anyhow!("no key found/invalid version in customer key"));
        }
        T::CustomerItem::decode_self(
            &sensitives
                .intermediate_key
                .decode_customer_key::<T>(key.unwrap().0.clone())?[..],
        )
    }

    pub fn decode_legacy_key<T: KeyhouseImpl + 'static>(&self) -> Result<Vec<u8>> {
        let sensitives = self
            .sensitives
            .as_ref()
            .ok_or_else(|| anyhow!("no sensitives on customer key"))?;
        let decoded = sensitives
            .intermediate_key
            .decode_customer_key::<T>(sensitives.legacy_key.data_key.clone())?;
        Ok(decoded)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct CustomerKeyMutation {
    pub description: Option<String>,
    pub acls: Option<BTreeMap<AccessControlDomain, AccessControlList>>,
    pub status: Option<KeyStatus>, // this is a NOP used for saying "reissue the key" from the control plane
    pub user_authorization_data: Option<Vec<String>>,
}

impl fmt::Display for CustomerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.clone().censor())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_key_reload() {
        let store: OwnedStore<()> = Arc::new(MockStore::new().await.unwrap());
        IntermediateKey::reload_checked(store.clone())
            .await
            .unwrap();
        let test_key = CustomerKey::new_base::<()>("test".to_string()).unwrap();
        store.store_customer_key(test_key.clone()).await.unwrap();
        assert_eq!(None, test_key.reload_checked(&store).await.unwrap());
        let mut test_key2 = CustomerKey::new_base::<()>("test2".to_string()).unwrap();
        test_key2.updated_at = 0;
        store.store_customer_key(test_key2.clone()).await.unwrap();
        let new_key = match test_key2.clone().reload_checked(&store).await.unwrap() {
            Some(key) => {
                assert_eq!(key.alias, test_key2.alias);
                assert_eq!(key.id, test_key2.id);
                assert_ne!(
                    key.sensitives.as_ref().unwrap().keys,
                    test_key2.sensitives.as_ref().unwrap().keys
                );
                key
            }
            None => panic!("key not reloaded"),
        };
        assert_eq!(
            new_key,
            store
                .get_customer_key_by_alias("test2")
                .await
                .unwrap()
                .unwrap()
        );
        assert_eq!(new_key.sensitives.as_ref().unwrap().keys.len(), 2);
        assert_eq!(
            new_key,
            store
                .get_customer_key_by_alias("test2")
                .await
                .unwrap()
                .unwrap()
        );
    }
}
