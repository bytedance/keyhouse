use super::*;
use sha2::Digest;

impl<T: KeyhouseImpl + 'static> KeyhouseService<T> {
    async fn encode_data_key(
        &self,
        spiffe_id: Option<&SpiffeID>,
        request: keyhouse::EncodeDataKeyRequest,
    ) -> Result<StdResult<keyhouse::EncodeDataKeyResponse, ErrorCode>> {
        let key = match self.load_key_from_alias(&request.alias).await? {
            Err(code) => return Ok(Err(code)),
            Ok(x) => x,
        };

        if key.purpose != KeyPurpose::EncodeDecode {
            return Ok(Err(ErrorCode::Forbidden));
        }
        match KeyhouseService::<T>::authorize_acls(
            spiffe_id,
            key.acls.get(&AccessControlDomain::Encode),
        ) {
            Ok(_) => (),
            Err(code) => return Ok(Err(code)),
        }

        // check if the sdk send the custom datakey
        let raw_key: Vec<u8>;
        let custom_raw_key: Vec<u8> = request.custom_raw_key;
        let key_out = if custom_raw_key.is_empty() {
            let client_coding_raw = key.generate_data_key::<T>()?;
            raw_key = client_coding_raw.into_source();
            key.decode_key::<T>(None)?.encode_data(client_coding_raw.into_source())?
        } else if custom_raw_key.len() > 512 {
            return Ok(Err(ErrorCode::BadPayload));
        } else {
            raw_key = custom_raw_key;
            key.decode_key::<T>(None)?.encode_data(raw_key.to_owned())?
        };

        let sensitives = key
            .sensitives
            .as_ref()
            .ok_or_else(|| anyhow!("no sensitives on customer key"))?;

        let formed = DataKey {
            key: key_out,
            key_id: key.id,
            key_version: (sensitives.keys.len() - 1) as u32,
            timestamp: util::epoch_minutes(),
        };
        let mut formed_out = vec![];
        formed
            .encode(&mut formed_out)
            .expect("insufficient buffer space for encode");

        Ok(Ok(keyhouse::EncodeDataKeyResponse {
            error_code: ErrorCode::Ok as i32,
            encoded_key: formed_out,
            decoded_key: raw_key,
        }))
    }

    pub(crate) async fn encode_data_key_wrap(
        &self,
        raw_request: Request<keyhouse::EncodeDataKeyRequest>,
        spiffe_id: Option<SpiffeID>,
        ip: String,
    ) -> StdResult<KeyhouseResponse<keyhouse::EncodeDataKeyResponse>, Status> {
        let spiffe_id_value = spiffe_id.as_ref().map(|x| x.to_string());
        let (token_spiffe_id, token_value) =
            KeyhouseService::<T>::extract_alt_token(&raw_request.get_ref().token);

        if token_spiffe_id.is_none() && token_value.is_none() && !&raw_request.get_ref().token.is_empty() {
            match spiffe_id_value.as_ref() {
                Some(s) => warn!("invalid token but cert is ok. ip: {} spiffe_id: {}", ip, s),
                None => warn!("invalid token and no valid cert either. ip: {}", ip),
            }
        }

        let total_spiffe_id = T::IdentityCombiner::spiffe_id_combiner(
            spiffe_id,
            token_spiffe_id,
            raw_request.get_ref().prefer_channel_identity,
        );
        let (auth_service, auth_user) = Self::get_auth_user_service(total_spiffe_id.as_ref());

        let request = raw_request.into_inner();
        let alias = request.alias.clone();
        let result = self
            .encode_data_key(total_spiffe_id.as_ref(), request)
            .await;
        let data_key_hash = if let Ok(Ok(response)) = &result {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&response.encoded_key[..]);
            Some(hex::encode(hasher.finalize()))
        } else {
            None
        };

        let error_code = match &result {
            Ok(Ok(_)) => ErrorCode::Ok,
            Ok(Err(code)) => *code,
            Err(_) => ErrorCode::Unknown,
        };
        LogEvent::DataLogEvent(DataLogEvent {
            occurred_at: crate::util::epoch(),
            request_type: DataRequestType::EncodeDataKey,
            spiffe_id: spiffe_id_value,
            token: token_value
                .map(|x| serde_json::to_string(&x).ok())
                .flatten(),
            auth_service,
            auth_user,
            ip,
            key_id: None,
            key_alias: Some(alias.clone()),
            data_key_hash,
            status: error_code,
            internal_failure: result.is_err(),
            message: result.as_ref().err().map(|x| format!("{:?}", x)),
        })
        .fire::<T>();

        let response = result
            .unwrap_or(Err(ErrorCode::Unknown))
            .unwrap_or_else(|e| keyhouse::EncodeDataKeyResponse {
                error_code: e as i32,
                encoded_key: vec![],
                decoded_key: vec![],
            });

        Ok(KeyhouseResponse {
            response,
            spiffe_id: total_spiffe_id,
            error_code,
            target_alias: Some(alias),
        })
    }
}
