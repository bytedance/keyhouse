use super::*;
use sha2::Digest;

impl<T: KeyhouseImpl + 'static> KeyhouseService<T> {
    async fn decode_data_key(
        &self,
        spiffe_id: Option<&SpiffeID>,
        request: keyhouse::DecodeDataKeyRequest,
        out_key_id: &mut Option<u32>,
    ) -> Result<StdResult<keyhouse::DecodeDataKeyResponse, ErrorCode>> {
        let (key_id, decoded) = match CustomerKey::pre_decode_data_key(&request.encoded_key[..]) {
            Err(_code) => return Ok(Err(ErrorCode::BadPayload)),
            Ok(x) => x,
        };

        let key = match self.load_key_from_id(key_id).await? {
            Err(code) => return Ok(Err(code)),
            Ok(x) => x,
        };
        out_key_id.replace(key_id);

        if key.purpose != KeyPurpose::EncodeDecode {
            return Ok(Err(ErrorCode::Forbidden));
        }
        match KeyhouseService::<T>::authorize_acls(
            spiffe_id,
            key.acls.get(&AccessControlDomain::Decode),
        ) {
            Ok(_) => (),
            Err(code) => return Ok(Err(code)),
        }
        let decoded_key = key.decode_data_key::<T>(decoded)?;

        Ok(Ok(keyhouse::DecodeDataKeyResponse {
            error_code: ErrorCode::Ok as i32,
            decoded_key,
        }))
    }

    pub(crate) async fn decode_data_key_wrap(
        &self,
        raw_request: Request<keyhouse::DecodeDataKeyRequest>,
        spiffe_id: Option<SpiffeID>,
        ip: String,
    ) -> StdResult<KeyhouseResponse<keyhouse::DecodeDataKeyResponse>, Status> {
        let spiffe_id_value = spiffe_id.as_ref().map(|x| x.to_string());
        let (token_spiffe_id, token_value) =
            KeyhouseService::<T>::extract_alt_token(&raw_request.get_ref().token);
        let total_spiffe_id = T::IdentityCombiner::spiffe_id_combiner(
            spiffe_id,
            token_spiffe_id,
            raw_request.get_ref().prefer_channel_identity,
        );
        let (auth_service, auth_user) = Self::get_auth_user_service(total_spiffe_id.as_ref());

        let request = raw_request.into_inner();
        let mut hasher = sha2::Sha256::new();
        hasher.update(&request.encoded_key[..]);
        let data_key_hash = Some(hex::encode(hasher.finalize()));

        let mut key_id = None::<u32>;
        let result = self
            .decode_data_key(total_spiffe_id.as_ref(), request, &mut key_id)
            .await;

        let error_code = match &result {
            Ok(Ok(_)) => ErrorCode::Ok,
            Ok(Err(code)) => *code,
            Err(_) => ErrorCode::Unknown,
        };
        LogEvent::DataLogEvent(DataLogEvent {
            occurred_at: crate::util::epoch(),
            request_type: DataRequestType::DecodeDataKey,
            spiffe_id: spiffe_id_value,
            token: token_value
                .map(|x| serde_json::to_string(&x).ok())
                .flatten(),
            auth_service,
            auth_user,
            ip,
            key_id,
            key_alias: None,
            data_key_hash,
            status: error_code,
            internal_failure: result.is_err(),
            message: result.as_ref().err().map(|x| format!("{:?}", x)),
        })
        .fire::<T>();
        let response = result
            .unwrap_or(Err(ErrorCode::Unknown))
            .unwrap_or_else(|e| keyhouse::DecodeDataKeyResponse {
                error_code: e as i32,
                decoded_key: vec![],
            });
        Ok(KeyhouseResponse {
            response,
            spiffe_id: total_spiffe_id,
            error_code,
            target_alias: None,
        })
    }
}
