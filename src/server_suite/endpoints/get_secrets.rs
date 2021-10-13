use super::*;
use std::collections::HashMap;

impl<T: KeyhouseImpl + 'static> KeyhouseService<T> {
    async fn get_secrets(
        &self,
        spiffe_id: Option<&SpiffeID>,
        request: keyhouse::GetSecretsRequest,
    ) -> Result<StdResult<keyhouse::GetSecretsResponse, ErrorCode>> {
        let mut decoded_secrets = HashMap::new();
        if request.alias.is_empty() {
            if spiffe_id.is_none() {
                return Ok(Err(ErrorCode::Unauthorized));
            }

            let target_component = T::KeyhouseExt::get_spiffe_primary_component();
            let target_value = spiffe_id.unwrap().get_component(&target_component);
            let keys = if let Some(target_value) = target_value {
                self.store
                    .get_all_customer_keys_by_acl_component(
                        Some(AccessControlDomain::GetSecret),
                        &target_component,
                        Some(target_value),
                    )
                    .await?
                    .into_iter()
            } else {
                vec![].into_iter()
            };
            let keys = keys.chain(
                self.store
                    .get_all_customer_keys_by_acl_component(
                        Some(AccessControlDomain::GetSecret),
                        &target_component,
                        None,
                    )
                    .await?
                    .into_iter(),
            );

            for key in keys {
                if key.purpose != KeyPurpose::Secret {
                    continue;
                }
                match KeyhouseService::<T>::authorize_acls(
                    spiffe_id,
                    key.acls.get(&AccessControlDomain::GetSecret),
                ) {
                    Ok(_) => (),
                    Err(_) => continue,
                }

                let secrets = self.store.get_key_secrets(&key.alias).await?;
                for secret in secrets.into_iter() {
                    decoded_secrets.insert(
                        secret.alias.clone(),
                        secret.decode::<T>(&key)?.value.clone(),
                    );
                }
            }
        } else {
            let key = match self.load_key_from_alias(&request.alias).await? {
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

            let secrets = self.store.get_key_secrets(&request.alias).await?;

            for secret in secrets.into_iter() {
                let (_, secret_alias) = split_last_alias(&secret.alias);
                decoded_secrets.insert(
                    secret_alias.to_string(),
                    secret.decode::<T>(&key)?.value.clone(),
                );
            }
        };

        Ok(Ok(keyhouse::GetSecretsResponse {
            error_code: ErrorCode::Ok as i32,
            secrets: decoded_secrets,
        }))
    }

    pub(crate) async fn get_secrets_wrap(
        &self,
        raw_request: Request<keyhouse::GetSecretsRequest>,
        spiffe_id: Option<SpiffeID>,
        ip: String,
    ) -> StdResult<KeyhouseResponse<keyhouse::GetSecretsResponse>, Status> {
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
        let key_alias = Some(request.alias.clone());
        let result = self.get_secrets(total_spiffe_id.as_ref(), request).await;

        let error_code = match &result {
            Ok(Ok(_)) => ErrorCode::Ok,
            Ok(Err(code)) => *code,
            Err(_) => ErrorCode::Unknown,
        };

        LogEvent::DataLogEvent(DataLogEvent {
            occurred_at: crate::util::epoch(),
            request_type: DataRequestType::GetSecrets,
            spiffe_id: spiffe_id_value,
            token: token_value,
            auth_service,
            auth_user,
            ip,
            key_id: None,
            key_alias: key_alias.clone(),
            data_key_hash: None,
            status: match &result {
                Ok(Ok(_)) => ErrorCode::Ok,
                Ok(Err(code)) => *code,
                Err(_) => ErrorCode::Unknown,
            },
            internal_failure: result.is_err(),
            message: result.as_ref().err().map(|x| format!("{:?}", x)),
        })
        .fire::<T>();

        let response = result
            .unwrap_or(Err(ErrorCode::Unknown))
            .unwrap_or_else(|e| keyhouse::GetSecretsResponse {
                error_code: e as i32,
                secrets: HashMap::new(),
            });
        Ok(KeyhouseResponse {
            response,
            spiffe_id: total_spiffe_id,
            error_code,
            target_alias: key_alias,
        })
    }
}
