pub mod mock;

use crate::prelude::*;

#[tonic::async_trait]
pub trait MasterKeyProvider: Send + Sync + Clone {
    async fn encode(key_id: &str, data: Vec<u8>) -> Result<Vec<u8>>;

    async fn decode(key_id: &str, data: Vec<u8>) -> Result<Vec<u8>>;
}
