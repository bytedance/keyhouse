use super::CustomerKey;
use crate::baseclient;
use crate::baseclient::ClientCoding;
use crate::prelude::*;
use crate::server_suite::config::SERVER_CONFIG;
use crate::util;
use crate::KeyhouseImpl;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct Secret {
    pub alias: String,
    #[serde(
        serialize_with = "util::vec_as_base64",
        deserialize_with = "util::vec_from_base64"
    )]
    pub value: Vec<u8>,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct DecodedSecret {
    pub alias: String,
    pub value: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub description: String,
}

impl DecodedSecret {
    pub fn new_base(alias: String, value: String) -> Self {
        DecodedSecret {
            alias,
            value,
            created_at: util::epoch(),
            updated_at: util::epoch(),
            description: String::new(),
        }
    }

    pub fn encode<T: KeyhouseImpl + 'static>(self, key: &CustomerKey) -> Result<Secret> {
        let (coder, encoded_key) = key.encode_data_key::<T>()?;
        let region_name = &SERVER_CONFIG.get().0.region;
        Ok(Secret {
            alias: self.alias.clone(),
            value: baseclient::encode_data(
                coder,
                encoded_key,
                baseclient::Region(
                    T::KeyhouseExt::region_from_name(region_name)
                        .ok_or_else(|| anyhow!("unknown region name in config: {}", region_name))?,
                ),
                self.value.clone().into(),
            )?,
            created_at: self.created_at,
            updated_at: self.updated_at,
            description: self.description.clone(),
        })
    }

    pub fn validate_size(&self) -> bool {
        self.value.as_bytes().len() <= 1024 * 16
    }
}

impl Secret {
    pub fn new_base(alias: String) -> Self {
        let mut secret: Vec<u8> = vec![0; 32];
        rand::thread_rng().fill_bytes(&mut secret[..]);

        Secret {
            alias,
            value: secret,
            created_at: util::epoch(),
            updated_at: util::epoch(),
            description: String::new(),
        }
    }

    pub fn empty_decoded(self) -> DecodedSecret {
        DecodedSecret {
            alias: self.alias.clone(),
            value: String::new(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            description: self.description.clone(),
        }
    }

    pub fn decode<T: KeyhouseImpl + 'static>(self, key: &CustomerKey) -> Result<DecodedSecret> {
        let mut decoded = baseclient::DecodedData::decode_data(self.value.clone())?;
        let region_name = &SERVER_CONFIG.get().0.region;

        if decoded.region
            != Some(baseclient::Region(
                T::KeyhouseExt::region_from_name(region_name)
                    .ok_or_else(|| anyhow!("unknown region name in config: {}", region_name))?,
            ))
        {
            return Err(anyhow!("invalid region for data key"));
        }

        let (key_id, data_key) =
            CustomerKey::pre_decode_data_key(&decoded.encoded_key.take().unwrap()[..])?;
        if key_id != key.id {
            return Err(anyhow!(
                "payload key id does not match given key id: {} vs {}",
                key.id,
                key_id
            ));
        }
        let decoded = decoded.final_decode(T::ClientCoding::from_source(
            &key.decode_data_key::<T>(data_key)?[..],
        )?)?;
        let value = String::from_utf8_lossy(&decoded[..]).to_string();

        Ok(DecodedSecret {
            alias: self.alias.clone(),
            value,
            created_at: self.created_at,
            updated_at: self.updated_at,
            description: self.description.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_secret_roundtrip() {
        let key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        let secret =
            DecodedSecret::new_base("test/test/test".to_string(), "test secret".to_string());
        let encoded_secret = secret.clone().encode::<()>(&key).unwrap();
        let decoded_secret = encoded_secret.clone().decode::<()>(&key).unwrap();
        assert_eq!(secret, decoded_secret);
        assert_ne!(secret.value.clone().into_bytes(), encoded_secret.value);
    }
}
