use crate::baseclient::*;
use crate::keyhouse::{self, ErrorCode};
use crate::prelude::*;
use notify::RecommendedWatcher;
use std::collections::HashMap;
use std::marker::PhantomData;
use tonic::transport::*;

pub struct KeyhouseClient<T: KeyhouseImpl + 'static> {
    token: String,
    primary: SubClient,
    secondaries: HashMap<Region, SubClient>,
    _watcher: Option<RecommendedWatcher>,
    _phantom: PhantomData<T>,
}

#[derive(Clone)]
struct SubClient {
    client: keyhouse::kms_client::KmsClient<Channel>,
    region: Region,
    tls_config: rustls::ClientConfig,
}

impl<T: KeyhouseImpl + 'static> KeyhouseClient<T> {
    async fn connect_sub(region: Region, tls_config: rustls::ClientConfig) -> Result<SubClient> {
        let client = Channel::builder(
            region
                .url::<T>()
                .ok_or_else(|| anyhow!("couldn't find url for region"))?
                .parse()?,
        )
        .tls_config(ClientTlsConfig::new().rustls_client_config(tls_config.clone()))?
        .connect()
        .await?;
        let client = keyhouse::kms_client::KmsClient::new(client);
        Ok(SubClient {
            client,
            region,
            tls_config,
        })
    }

    async fn resolve_sub(&mut self, region: Region) -> Result<&mut SubClient> {
        if self.primary.region == region {
            Ok(&mut self.primary)
        } else if self.secondaries.contains_key(&region) {
            // no match/if-let possible due to bad borrow tracker handling here
            Ok(self.secondaries.get_mut(&region).unwrap())
        } else {
            let new_client =
                KeyhouseClient::<T>::connect_sub(region.clone(), self.primary.tls_config.clone())
                    .await?;
            self.secondaries.insert(region.clone(), new_client);
            Ok(self
                .secondaries
                .get_mut(&region)
                .ok_or_else(|| anyhow!("secondary missing after insertion"))?)
        }
    }

    pub async fn connect(region: Region, tls_config: rustls::ClientConfig) -> Result<Self> {
        let client = Self::connect_sub(region, tls_config).await?;
        Ok(KeyhouseClient {
            token: String::new(),
            primary: client,
            secondaries: HashMap::new(),
            _watcher: None,
            _phantom: PhantomData::<T>,
        })
    }

    pub async fn encode_data(&mut self, alias: String, input: Vec<u8>) -> Result<Vec<u8>> {
        let (coder, encoded_key) = self.encode_data_key(alias.clone(), Vec::default()).await?;
        encode_data(coder, encoded_key, self.primary.region.clone(), input)
    }

    pub async fn decode_data(&mut self, input: Vec<u8>) -> Result<Vec<u8>> {
        let mut decoded = DecodedData::decode_data(input)?;
        let coder = self
            .decode_data_key(
                decoded.region.take().unwrap(),
                decoded.encoded_key.take().unwrap(),
            )
            .await?;

        decoded.final_decode(coder)
    }

    /// returns coder context, encoded key
    pub async fn encode_data_key(&mut self, alias: String, custom_raw_key: Vec<u8>) -> Result<(T::ClientCoding, Vec<u8>)> {
        let request = tonic::Request::new(keyhouse::EncodeDataKeyRequest {
            token: self.token.clone(),
            alias,
            prefer_channel_identity: false,
            custom_raw_key,
        });
        let response = self
            .primary
            .client
            .encode_data_key(request)
            .await?
            .into_inner();
        let error_code = ErrorCode::from_primitive(response.error_code as usize);

        if error_code != ErrorCode::Ok {
            return Err(anyhow!("received error from server: {:?}", error_code));
        }
        Ok((
            T::ClientCoding::from_source(&response.decoded_key[..])?,
            response.encoded_key,
        ))
    }

    pub async fn decode_data_key(&mut self, region: Region, key: Vec<u8>) -> Result<T::ClientCoding> {
        let request = tonic::Request::new(keyhouse::DecodeDataKeyRequest {
            token: self.token.clone(),
            encoded_key: key,
            prefer_channel_identity: false,
        });
        let response = self
            .resolve_sub(region)
            .await?
            .client
            .decode_data_key(request)
            .await?
            .into_inner();
        let error_code = ErrorCode::from_primitive(response.error_code as usize);
        if error_code != ErrorCode::Ok {
            return Err(anyhow!("received error from server: {:?}", error_code));
        }
        Ok(T::ClientCoding::from_source(&response.decoded_key[..])?)
    }

    pub async fn ping_pong(&mut self, timestamp: u128) -> Result<u128> {
        let request = tonic::Request::new(keyhouse::PingPongRequest {
            token: self.token.clone(),
            timestamp: timestamp.to_le_bytes().to_vec(),
            prefer_channel_identity: false,
        });
        let response = self.primary.client.ping_pong(request).await?;
        let error_code = response.get_ref().error_code;
        if error_code != 0 {
            return Err(anyhow!("ping_pong error code: {}", error_code));
        }

        let timestamp_vec = response.into_inner().timestamp;
        if timestamp_vec.len() != 16 {
            return Err(anyhow!("invalid response length: {}", timestamp_vec.len()));
        }
        let mut timestamp: [u8; 16] = [0; 16];
        timestamp.copy_from_slice(&timestamp_vec[..]);

        Ok(u128::from_le_bytes(timestamp))
    }

    pub async fn get_secret(&mut self, alias: String) -> Result<String> {
        let request = tonic::Request::new(keyhouse::GetSecretRequest {
            token: self.token.clone(),
            alias,
            prefer_channel_identity: false,
        });
        let response = self.primary.client.get_secret(request).await?.into_inner();
        let error_code = ErrorCode::from_primitive(response.error_code as usize);

        if error_code != ErrorCode::Ok {
            return Err(anyhow!("received error from server: {:?}", error_code));
        }
        Ok(response.secret)
    }

    pub async fn get_secrets(&mut self, alias: String) -> Result<HashMap<String, String>> {
        let request = tonic::Request::new(keyhouse::GetSecretsRequest {
            token: self.token.clone(),
            alias,
            prefer_channel_identity: false,
        });
        let response = self.primary.client.get_secrets(request).await?.into_inner();
        let error_code = ErrorCode::from_primitive(response.error_code as usize);

        if error_code != ErrorCode::Ok {
            return Err(anyhow!("received error from server: {:?}", error_code));
        }
        Ok(response.secrets)
    }

    pub async fn store_secret<Y: Into<String>>(&mut self, alias: String, secret: Y) -> Result<()> {
        let request = tonic::Request::new(keyhouse::StoreSecretRequest {
            token: self.token.clone(),
            alias,
            secret: secret.into(),
            prefer_channel_identity: false,
        });
        let response = self
            .primary
            .client
            .store_secret(request)
            .await?
            .into_inner();
        let error_code = ErrorCode::from_primitive(response.error_code as usize);

        if error_code != ErrorCode::Ok {
            return Err(anyhow!("received error from server: {:?}", error_code));
        }
        Ok(())
    }

    pub async fn get_legacy_key(&mut self, alias: String) -> Result<Vec<u8>> {
        let request = tonic::Request::new(keyhouse::GetLegacyKeyRequest {
            token: self.token.clone(),
            alias,
            prefer_channel_identity: false,
        });
        let response = self
            .primary
            .client
            .get_legacy_key(request)
            .await?
            .into_inner();
        let error_code = ErrorCode::from_primitive(response.error_code as usize);

        if error_code != ErrorCode::Ok {
            return Err(anyhow!("received error from server: {:?}", error_code));
        }
        Ok(response.data_key)
    }

    pub fn secondary_count(&self) -> usize {
        self.secondaries.len()
    }
}
