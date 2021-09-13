use super::*;
use crate::server_suite::store::CacheInvalidation;

impl<T: KeyhouseImpl + 'static> KeyhouseService<T> {
    async fn store_secret(
        &self,
        spiffe_id: Option<&SpiffeID>,
        request: keyhouse::StoreSecretRequest,
    ) -> Result<StdResult<keyhouse::StoreSecretResponse, ErrorCode>> {
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
            key.acls.get(&AccessControlDomain::StoreSecret),
        ) {
            Ok(_) => (),
            Err(code) => return Ok(Err(code)),
        }

        const STORE_RETRY_COUNT: usize = 3;
        for i in 0..STORE_RETRY_COUNT {
            self.store
                .cache_invalidation(&CacheInvalidation::Secret {
                    alias: request.alias.clone(),
                })
                .await?;

            let secret = self.store.get_secret(&request.alias).await?;
            let new_secret = match &secret {
                Some(secret) => DecodedSecret {
                    alias: secret.alias.clone(),
                    value: request.secret.clone(),
                    updated_at: util::epoch(),
                    created_at: secret.created_at,
                    description: secret.description.clone(),
                },
                None => DecodedSecret {
                    alias: request.alias.clone(),
                    value: request.secret.clone(),
                    created_at: util::epoch(),
                    updated_at: util::epoch(),
                    description: "Created from Data Plane store_secret".to_string(),
                },
            };
            if !new_secret.validate_size() {
                return Ok(Err(ErrorCode::BadPayload));
            }
            if secret.is_none() {
                if let Some(max_secret_count) = SERVER_CONFIG.get().0.secret_limit {
                    if self.store.count_key_secrets(key_alias).await? >= max_secret_count {
                        return Ok(Err(ErrorCode::Forbidden));
                    }
                }
            }

            let new_secret = new_secret.encode::<T>(&key)?;

            if let Err(e) = self.store.store_secret(secret, new_secret).await {
                if i == STORE_RETRY_COUNT - 1 {
                    return Err(e);
                } else {
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    continue;
                }
            }
            break;
        }
        Ok(Ok(keyhouse::StoreSecretResponse {
            error_code: ErrorCode::Ok as i32,
        }))
    }

    pub(crate) async fn store_secret_wrap(
        &self,
        raw_request: Request<keyhouse::StoreSecretRequest>,
        spiffe_id: Option<SpiffeID>,
        ip: String,
    ) -> StdResult<KeyhouseResponse<keyhouse::StoreSecretResponse>, Status> {
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
        let key_alias = Some(request.alias.clone());
        let result = self.store_secret(total_spiffe_id.as_ref(), request).await;

        let error_code = match &result {
            Ok(Ok(_)) => ErrorCode::Ok,
            Ok(Err(code)) => *code,
            Err(_) => ErrorCode::Unknown,
        };

        LogEvent::DataLogEvent(DataLogEvent {
            occurred_at: crate::util::epoch(),
            request_type: DataRequestType::StoreSecret,
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
            .unwrap_or_else(|e| keyhouse::StoreSecretResponse {
                error_code: e as i32,
            });
        Ok(KeyhouseResponse {
            response,
            spiffe_id: total_spiffe_id,
            error_code,
            target_alias: key_alias,
        })
    }
}
