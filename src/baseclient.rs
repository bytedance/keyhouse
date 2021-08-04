use crate::customer_key::*;
use crate::prelude::*;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

pub const DATA_KEY_ENCODED_VERSION: u32 = 0;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Region(pub Vec<u8>);

impl Region {
    pub fn url<T: KeyhouseImpl + 'static>(&self) -> Option<String> {
        T::KeyhouseExt::region_url(&self.0[..])
    }
}

pub trait ClientCoding: Sized {
    fn generate() -> Self;

    fn generate_seed() -> Vec<u8>;

    fn generate_epoch(seed: Vec<u8>, epoch: u64) -> Self;

    fn from_source(source: &[u8]) -> Result<Self>;

    #[allow(clippy::wrong_self_convention)]
    fn into_source(&self) -> Vec<u8>;

    fn encode_data(&mut self, input: Vec<u8>) -> Result<Vec<u8>>;

    fn decode_data(&mut self, input: Vec<u8>) -> Result<Vec<u8>>;

    // MUST NOT PREPEND IV
    fn encode_data_with_iv(&mut self, input: Vec<u8>, iv: &[u8]) -> Result<Vec<u8>>;

    fn decode_data_with_iv(&mut self, input: Vec<u8>, iv: &[u8]) -> Result<Vec<u8>>;
}

const DATA_FOR_EMPTY: &[u8] = &[
    0, 9, 8, 7, 6, 5, 4, 3, 0, 9, 8, 7, 6, 5, 4, 3, 0, 9, 8, 7, 6, 5, 4, 3, 0, 9, 8, 7, 6, 5, 4, 3,
];

#[tonic::async_trait]
impl crate::baseclient::ClientCoding for () {
    fn generate() -> Self {}

    fn generate_seed() -> Vec<u8> {
        // generate a seed used for generate_epoch
        DATA_FOR_EMPTY.to_vec()
    }

    fn generate_epoch(_seed: Vec<u8>, _epoch: u64) -> Self {
        // generate Self with, for example, a cryptographically secure PRNG seeded with seed[0..8] ^ (epoch as Vec<u8>)
    }

    fn from_source(source: &[u8]) -> Result<Self> {
        if source != DATA_FOR_EMPTY {
            return Err(anyhow!("invalid self for () clientcoding"));
        }
        Ok(())
    }

    fn into_source(&self) -> Vec<u8> {
        DATA_FOR_EMPTY.to_vec()
    }

    fn encode_data(&mut self, input: Vec<u8>) -> Result<Vec<u8>> {
        self.encode_data_with_iv(input, &[])
    }

    fn decode_data(&mut self, input: Vec<u8>) -> Result<Vec<u8>> {
        self.decode_data_with_iv(input, &[])
    }

    fn encode_data_with_iv(&mut self, mut input: Vec<u8>, _iv: &[u8]) -> Result<Vec<u8>> {
        if !input.is_empty() {
            input[0] = input[0].wrapping_add(1);
        }
        input.reverse();
        Ok(input)
    }

    fn decode_data_with_iv(&mut self, mut input: Vec<u8>, _iv: &[u8]) -> Result<Vec<u8>> {
        input.reverse();
        if !input.is_empty() {
            input[0] = input[0].wrapping_sub(1);
        }
        Ok(input)
    }
}

pub fn encode_data<T: ClientCoding + 'static>(
    mut coder: T,
    encoded_key: Vec<u8>,
    region: Region,
    input: Vec<u8>,
) -> Result<Vec<u8>> {
    let output = coder.encode_data(input)?;
    let formed = EncodedBlob {
        data: output,
        version: DATA_KEY_ENCODED_VERSION,
        encoded_key,
        region: region.0,
    };
    let mut formed_out = vec![];
    formed.encode(&mut formed_out)?;
    formed_out.extend_from_slice(&crc::crc32::checksum_ieee(&formed_out[..]).to_le_bytes()[..]);
    Ok(formed_out)
}

pub struct DecodedData {
    data: Vec<u8>,
    pub region: Option<Region>,
    pub encoded_key: Option<Vec<u8>>,
}

impl DecodedData {
    pub fn final_decode<T: ClientCoding + 'static>(self, mut coder: T) -> Result<Vec<u8>> {
        let output = coder.decode_data(self.data)?;
        Ok(output)
    }

    pub fn decode_data(input: Vec<u8>) -> Result<DecodedData> {
        let len = input.len();
        if len < 4 {
            return Err(anyhow!("payload too short"));
        }
        let crc32 = u32::from_le_bytes((&input[len - 4..]).try_into()?);
        if crc32 != crc::crc32::checksum_ieee(&input[0..len - 4]) {
            return Err(anyhow!("malformed input! crc32 mismatch"));
        }
        let decoded = EncodedBlob::decode(&input[0..len - 4])?;

        if decoded.version != DATA_KEY_ENCODED_VERSION {
            return Err(anyhow!(
                "unknown data version encountered: {}, expected {}",
                decoded.version,
                DATA_KEY_ENCODED_VERSION
            ));
        }

        let region = Region(decoded.region.clone());

        Ok(DecodedData {
            data: decoded.data,
            region: Some(region),
            encoded_key: Some(decoded.encoded_key),
        })
    }
}
