use crate::master_key::MasterKeyProvider;
use crate::prelude::*;

#[derive(Clone)]
pub struct MockMasterKey;

#[tonic::async_trait]
impl MasterKeyProvider for MockMasterKey {
    async fn encode(_key_id: &str, mut data: Vec<u8>) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(data);
        }
        data.reverse();
        data[0] = data[0].wrapping_add(1); // to prevent encode = decode
        Ok(data)
    }

    async fn decode(_key_id: &str, mut data: Vec<u8>) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(data);
        }
        data[0] = data[0].wrapping_sub(1); // to prevent encode = decode
        data.reverse();
        Ok(data)
    }
}
