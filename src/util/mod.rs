pub mod dynamic_config;
pub mod time;

pub use time::{epoch, epoch_minutes, epoch_us};

use serde::{de::Error, Deserialize, Deserializer, Serializer};

#[allow(clippy::ptr_arg)]
pub fn vec_as_base64<S: Serializer>(key: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&base64::encode(&key[..]))
}

pub fn vec_from_base64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    String::deserialize(deserializer)
        .and_then(|string| base64::decode(&string).map_err(|err| Error::custom(err.to_string())))
}
