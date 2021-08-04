use super::*;

impl<T: KeyhouseImpl + 'static> KeyhouseService<T> {
    async fn get_secret(
        &self,
        spiffe_id: Option<&SpiffeID>,
        request: keyhouse::GetSecretRequest,
    ) -> Result<StdResult<keyhouse::GetSecretResponse, ErrorCode>> {
        let (key_alias, _secret_alias) = split_last_alias(&request.alias);

        let key = match self.load_key_from_alias(key_alias).await? {
            Err(code) => return Ok(Err(code)),
            Ok(x) => x,
        };
        if key.purpose != KeyPurpose::Secret {
            return Ok(Err(ErrorCode::Forbidden));
        }
        match KeyhouseService::<T>::authorize_acls(
            spiffe_id,
            key.acls.get(&AccessControlDomain::GetSecret),
        ) {
            Ok(_) => (),
            Err(code) => return Ok(Err(code)),
        }

        let secret = match self.store.get_secret(&request.alias).await? {
            Some(secret) => secret,
            None => return Ok(Err(ErrorCode::UnknownAlias)),
        };

        let decoded_secret = secret.decode::<T>(&key)?;

        Ok(Ok(keyhouse::GetSecretResponse {
            error_code: ErrorCode::Ok as i32,
            secret: decoded_secret.value.clone(),
        }))
    }

    pub(crate) async fn get_secret_wrap(
        &self,
        raw_request: Request<keyhouse::GetSecretRequest>,
        spiffe_id: Option<SpiffeID>,
        ip: String,
    ) -> StdResult<KeyhouseResponse<keyhouse::GetSecretResponse>, Status> {
        let spiffe_id_value = spiffe_id.as_ref().map(|x| x.to_string());
        let (token_spiffe_id, token_value) =
            KeyhouseService::<T>::extract_alt_token(&raw_request.get_ref().token);
        let total_spiffe_id = spiffe_id.as_ref().or_else(|| token_spiffe_id.as_ref());
        let (auth_service, auth_user) = Self::get_auth_user_service(total_spiffe_id);

        let request = raw_request.into_inner();
        let key_alias = Some(request.alias.clone());
        let result = self.get_secret(total_spiffe_id, request).await;

        let error_code = match &result {
            Ok(Ok(_)) => ErrorCode::Ok,
            Ok(Err(code)) => *code,
            Err(_) => ErrorCode::Unknown,
        };

        LogEvent::DataLogEvent(DataLogEvent {
            occurred_at: crate::util::epoch(),
            request_type: DataRequestType::GetSecret,
            spiffe_id: spiffe_id_value,
            token: token_value,
            auth_service,
            auth_user,
            ip,
            key_id: None,
            key_alias: key_alias.clone(),
            data_key_hash: None,
            status: error_code,
            internal_failure: result.is_err(),
            message: result.as_ref().err().map(|x| format!("{:?}", x)),
        })
        .fire::<T>();

        let response = result
            .unwrap_or(Err(ErrorCode::Unknown))
            .unwrap_or_else(|e| keyhouse::GetSecretResponse {
                error_code: e as i32,
                secret: "".to_string(),
            });
        Ok(KeyhouseResponse {
            response,
            spiffe_id: total_spiffe_id.cloned(),
            error_code,
            target_alias: key_alias,
        })
    }
}
