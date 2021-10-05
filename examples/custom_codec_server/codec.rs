use anyhow::*;
use keyhouse::baseclient::ClientCoding;
use keyhouse::server_suite::coding::CodingItem;
use ring::aead;
use ring::aead::{Nonce, NonceSequence};
use ring::error::Unspecified;
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};

const KEYSIZE: usize = 32;

#[derive(Clone, Debug, PartialEq)]
pub struct AES256GCMCodec;

#[derive(Clone, Debug, PartialEq)]
pub struct AES256GCMCodecItem {
    key: [u8; 32],
    counter: u64,
}

pub struct KeyHouseNonceSequence(Result<aead::Nonce, Unspecified>, Vec<u8>);

impl KeyHouseNonceSequence {
    fn gen_nonce() -> Self {
        let rng = SystemRandom::new();
        let mut randombytes: [u8; aead::NONCE_LEN] = [0; aead::NONCE_LEN];
        let _ = rng
            .fill(&mut randombytes)
            .map_err(|e| Self(Err(e), randombytes.to_vec()));
        let raw_nonce = &randombytes[..];
        Self(
            aead::Nonce::try_assume_unique_for_key(raw_nonce),
            raw_nonce.to_vec(),
        )
    }

    fn gen_nonce_from_iv(iv: &[u8]) -> Self {
        if iv.len() != aead::NONCE_LEN {
            return Self(Err(Unspecified), iv.to_vec());
        }
        Self(aead::Nonce::try_assume_unique_for_key(iv), iv.to_vec())
    }

    fn get_raw_bytes(&self) -> Vec<u8> {
        self.1.clone()
    }

    fn new() -> Self {
        KeyHouseNonceSequence::gen_nonce()
    }
}

impl NonceSequence for KeyHouseNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        KeyHouseNonceSequence::gen_nonce().0
    }
}

fn new_aes256gcm_codec_item() -> AES256GCMCodecItem {
    let mut codec_item = AES256GCMCodecItem {
        key: [0; KEYSIZE],
        counter: 0,
    };
    let rng = SystemRandom::new();
    rng.fill(&mut codec_item.key).unwrap();
    codec_item
}

fn load_aes256gcm_codec_item(source: &[u8]) -> Result<AES256GCMCodecItem> {
    if source.len() != KEYSIZE {
        return Err(anyhow!("invalid source length"));
    }
    let mut codec_item = AES256GCMCodecItem {
        key: [0; KEYSIZE],
        counter: 0,
    };
    codec_item.key.clone_from_slice(source);
    Ok(codec_item)
}

fn dump_aes256gcm_codec_item(item: &AES256GCMCodecItem) -> Vec<u8> {
    item.key.to_vec()
}

fn aes256gcm_encrypt_with_iv(
    item: &AES256GCMCodecItem,
    mut data: Vec<u8>,
    nonce_sequence: KeyHouseNonceSequence,
) -> Result<Vec<u8>> {
    data.reserve(aead::MAX_TAG_LEN);
    let mut sealing_key: aead::SealingKey<KeyHouseNonceSequence> =
        match make_key(&aead::AES_256_GCM, &item.key, Some(nonce_sequence)) {
            Ok(key) => key,
            Err(e) => return Err(anyhow::Error::from(e)),
        };
    sealing_key.seal_in_place_append_tag(aead::Aad::empty(), &mut data)?;
    Ok(data)
}

fn aes256gcm_decrypt_with_iv(
    item: &AES256GCMCodecItem,
    data: &mut [u8],
    nonce_sequence: KeyHouseNonceSequence,
) -> Result<Vec<u8>> {
    let mut opening_key: aead::OpeningKey<KeyHouseNonceSequence> =
        match make_key(&aead::AES_256_GCM, &item.key, Some(nonce_sequence)) {
            Ok(key) => key,
            Err(e) => return Err(anyhow::Error::from(e)),
        };
    let plaintext = opening_key.open_in_place(aead::Aad::empty(), data)?;
    Ok(plaintext.to_vec())
}

fn aes256gcm_encrypt(item: &AES256GCMCodecItem, data: Vec<u8>) -> Result<Vec<u8>> {
    let nonce_sequence = KeyHouseNonceSequence::new();
    let mut output = nonce_sequence.get_raw_bytes();
    let ciphertext = aes256gcm_encrypt_with_iv(item, data, nonce_sequence)?;
    output.extend(ciphertext.iter());
    Ok(output)
}

fn aes256gcm_decrypt(item: &AES256GCMCodecItem, mut data: Vec<u8>) -> Result<Vec<u8>> {
    if data.len() < aead::AES_256_GCM.tag_len() + aead::NONCE_LEN {
        return Err(anyhow!("invalid data length"));
    }
    let (raw_nonce, ciphertext) = data.split_at_mut(aead::NONCE_LEN);
    let nonce_sequence = KeyHouseNonceSequence::gen_nonce_from_iv(raw_nonce);
    aes256gcm_decrypt_with_iv(item, ciphertext, nonce_sequence)
}

fn make_key<K: aead::BoundKey<KeyHouseNonceSequence>>(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce_sequence: Option<KeyHouseNonceSequence>,
) -> Result<K, Unspecified> {
    let key = aead::UnboundKey::new(algorithm, key)?;
    let nonce_sequence = match nonce_sequence {
        Some(nonce_seq) => nonce_seq,
        None => KeyHouseNonceSequence::new(),
    };
    Ok(K::new(key, nonce_sequence))
}

impl ClientCoding for AES256GCMCodecItem {
    fn generate() -> Self {
        new_aes256gcm_codec_item()
    }

    fn generate_seed() -> Vec<u8> {
        let mut seed: [u8; 16] = [0; 16];
        let rng = SystemRandom::new();
        rng.fill(&mut seed).unwrap();
        seed.to_vec()
    }

    fn generate_epoch(seed: Vec<u8>, epoch: u64) -> Self {
        let raw_salt = epoch.to_be_bytes();
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &raw_salt);
        let prk = salt.extract(&seed);
        let okm = prk.expand(&[], &aead::AES_256_GCM).unwrap();
        let mut coding_item = AES256GCMCodecItem {
            key: [0; KEYSIZE],
            counter: 0,
        };
        okm.fill(&mut coding_item.key).unwrap();
        coding_item
    }

    fn from_source(source: &[u8]) -> Result<Self> {
        load_aes256gcm_codec_item(source)
    }

    fn into_source(&self) -> Vec<u8> {
        dump_aes256gcm_codec_item(self)
    }

    fn encode_data(&mut self, input: Vec<u8>) -> Result<Vec<u8>> {
        self.counter += 1;
        aes256gcm_encrypt(self, input)
    }

    fn decode_data(&mut self, input: Vec<u8>) -> Result<Vec<u8>> {
        aes256gcm_decrypt(self, input)
    }

    fn encode_data_with_iv(&mut self, input: Vec<u8>, iv: &[u8]) -> Result<Vec<u8>> {
        self.counter += 1;
        if iv.len() != aead::NONCE_LEN {
            return Err(anyhow!("invalid iv length"));
        }
        let nonce_sequence = KeyHouseNonceSequence::gen_nonce_from_iv(iv);
        aes256gcm_encrypt_with_iv(self, input, nonce_sequence)
    }

    fn decode_data_with_iv(&mut self, mut input: Vec<u8>, iv: &[u8]) -> Result<Vec<u8>> {
        let nonce_sequence = KeyHouseNonceSequence::gen_nonce_from_iv(iv);
        aes256gcm_decrypt_with_iv(self, &mut input[..], nonce_sequence)
    }
}

impl CodingItem for AES256GCMCodecItem {
    fn generate() -> Self {
        new_aes256gcm_codec_item()
    }

    fn encode_data(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        aes256gcm_encrypt(self, input)
    }

    fn decode_data(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        aes256gcm_decrypt(self, input)
    }

    fn encode_self(&self) -> Result<Vec<u8>> {
        Ok(self.key.to_vec())
    }

    fn decode_self(raw: &[u8]) -> Result<Self> {
        if raw.len() != KEYSIZE {
            return Err(anyhow!("invalid source length"));
        }
        let mut codec_item = AES256GCMCodecItem {
            key: [0; KEYSIZE],
            counter: 0,
        };
        codec_item.key.clone_from_slice(raw);
        Ok(codec_item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_aes256gcm_codec_item_with_iv() {
        let mut cc: AES256GCMCodecItem = ClientCoding::generate();
        println!("secret:{}\n", hex::encode(cc.encode_self().unwrap()));
        let plaintext = String::from("exampleplaintext").into_bytes();
        let plaintext_copy = plaintext.clone();
        let rng = SystemRandom::new();
        let mut randombytes: [u8; aead::NONCE_LEN] = [0; aead::NONCE_LEN];
        rng.fill(&mut randombytes).unwrap();
        let enc_result = ClientCoding::encode_data_with_iv(&mut cc, plaintext_copy, &randombytes);
        assert!(enc_result.is_ok());
        let ciphertext = enc_result.unwrap();
        let mut ciphertext_copy = ciphertext.clone();
        println!("ciphertext:{}\n", hex::encode(&ciphertext));
        let dec_result = cc.decode_data_with_iv(ciphertext, &randombytes);
        assert!(dec_result.is_ok());
        let plaintext_dec = dec_result.unwrap();
        assert_eq!(plaintext_dec, plaintext);

        let mut ciphertext_with_iv = randombytes.to_vec();
        ciphertext_with_iv.append(&mut ciphertext_copy);

        let ya_dec_result = cc.decode_data(ciphertext_with_iv);
        assert!(ya_dec_result.is_ok());
        assert_eq!(ya_dec_result.unwrap(), plaintext);
    }

    #[test]
    fn test_aes256gcm_codec_item() {
        let mut cc: AES256GCMCodecItem = ClientCoding::generate();
        println!("secret:{}\n", hex::encode(cc.encode_self().unwrap()));
        let plaintext = String::from("exampleplaintext").into_bytes();
        let plaintext_copy = plaintext.clone();
        let enc_result = ClientCoding::encode_data(&mut cc, plaintext_copy);
        assert!(enc_result.is_ok());
        let ciphertext = enc_result.unwrap();
        println!("ciphertext:{}\n", hex::encode(&ciphertext));
        let ciphertext_copy = ciphertext.clone();

        let dec_result = cc.decode_data(ciphertext_copy);
        assert!(dec_result.is_ok());
        let plaintext_dec = dec_result.unwrap();
        assert_eq!(plaintext_dec, plaintext);

        let mut ciphertext_ya_copy = ciphertext.clone();
        ciphertext_ya_copy[1] = ciphertext_ya_copy[1] + 1;

        let ya_dec_result = cc.decode_data(ciphertext_ya_copy);
        assert!(ya_dec_result.is_err());

        let ex_key = cc.encode_self().unwrap();
        let ya_cc: AES256GCMCodecItem = ClientCoding::from_source(ex_key.as_slice()).unwrap();
        let ciphertext_copy = ciphertext.clone();
        let dec_result = ya_cc.decode_data(ciphertext_copy);
        assert!(dec_result.is_ok());
        let plaintext_dec = dec_result.unwrap();
        assert_eq!(plaintext_dec, plaintext);
    }

    #[test]
    fn test_decrypt() {
        let decrypt_closure = |hex_key: &str, hex_ciphertext: &str| {
            let plaintext = String::from("exampleplaintext").into_bytes();
            let key = hex::decode(hex_key).unwrap();
            let ciphertext = hex::decode(hex_ciphertext).unwrap();
            let cc: AES256GCMCodecItem = CodingItem::decode_self(key.as_slice()).unwrap();
            let dec_result = cc.decode_data(ciphertext);
            assert!(dec_result.is_ok());
            let plaintext_dec = dec_result.unwrap();
            assert_eq!(plaintext_dec, plaintext);
        };
        //case1: decrypt c generated
        decrypt_closure("0CEB83DE0659C1F1D64032E4911E1A278D6A1DE705DE3E191E4E86782AFD9BB0", "F9C12403C74AAE74AAAD0DACF9922ADF0EF8EFAD68541184561503D6F7E7B753E674A8154B8AA70B3FC6E44F");
        //case2: decrypt go generated
        decrypt_closure("74ab0561bb2a381304dec4d7fe1dda666a922d9ded0703b920e247213f31f96b", "91d5bc9c56f6c51693c2e1861df246237f5d0658b211205c653b073de290e24d8e0a2d5c9d77caf0f2581dd4");
        //case3: decrypt java generated
        decrypt_closure("2A0C172BBEE820B451067C19C23EA391C1BB65CE662E83385875878B4CA7E572", "5754AE5D6C2191B68D3E93367097A814090DFFD99C3F53188CC7694FA1C4120F8D941608329A45865187E6A9");
        //case4: decrypt rust generated
        decrypt_closure("bd14c666ced2dd4707a06d2701bf1bd21f1c29ba4ead46f309394ceea266780d", "16b9ae45a24fa87018a6b740eff2492a83b9b9fb5e937f3345a6b5af6461bba1a182edfa35652d932c898497");
    }

    #[test]
    fn test_generate_by_seed_and_epoch() {
        let seed = AES256GCMCodecItem::generate_seed();
        let seed1 = seed.clone();
        let seed2 = seed.clone();
        let cc0 = AES256GCMCodecItem::generate_epoch(seed, 0);
        assert!(cc0.encode_self().is_ok());
        let yacc0 = AES256GCMCodecItem::generate_epoch(seed1, 0);
        assert!(yacc0.encode_self().is_ok());
        let cc1 = AES256GCMCodecItem::generate_epoch(seed2, 1);
        assert!(cc1.encode_self().is_ok());
        assert_eq!(cc0.encode_self().unwrap(), yacc0.encode_self().unwrap());
        assert_ne!(cc0.encode_self().unwrap(), cc1.encode_self().unwrap());
    }
}
