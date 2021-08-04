use crate::prelude::*;

pub trait CodingItem: Send + Sync + Clone + std::fmt::Debug + PartialEq {
    fn generate() -> Self;

    fn encode_data(&self, input: Vec<u8>) -> Result<Vec<u8>>;

    fn decode_data(&self, input: Vec<u8>) -> Result<Vec<u8>>;

    fn encode_self(&self) -> Result<Vec<u8>>;

    fn decode_self(raw: &[u8]) -> Result<Self>;
}

const DATA_FOR_EMPTY: &[u8] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
];

impl CodingItem for () {
    fn generate() -> Self {}

    fn encode_data(&self, mut input: Vec<u8>) -> Result<Vec<u8>> {
        if !input.is_empty() {
            input[0] = input[0].wrapping_add(1);
        }
        input.reverse();
        Ok(input)
    }

    fn decode_data(&self, mut input: Vec<u8>) -> Result<Vec<u8>> {
        input.reverse();
        if !input.is_empty() {
            input[0] = input[0].wrapping_sub(1);
        }
        Ok(input)
    }

    fn encode_self(&self) -> Result<Vec<u8>> {
        Ok(DATA_FOR_EMPTY.to_vec())
    }

    fn decode_self(raw: &[u8]) -> Result<Self> {
        if raw != DATA_FOR_EMPTY {
            return Err(anyhow!("invalid self for () coding"));
        }
        Ok(())
    }
}
