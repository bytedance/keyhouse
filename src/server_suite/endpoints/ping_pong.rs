use super::*;

impl<T: KeyhouseImpl + 'static> KeyhouseService<T> {
    pub(crate) async fn ping_pong_wrap(
        &self,
        raw_request: Request<keyhouse::PingPongRequest>,
        spiffe_id: Option<SpiffeID>,
        ip: String,
    ) -> StdResult<KeyhouseResponse<keyhouse::PingPongResponse>, Status> {
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
        LogEvent::DataLogEvent(DataLogEvent {
            occurred_at: crate::util::epoch(),
            request_type: DataRequestType::PingPong,
            spiffe_id: spiffe_id_value,
            token: token_value
                .map(|x| serde_json::to_string(&x).ok())
                .flatten(),
            auth_service,
            auth_user,
            ip,
            key_id: None,
            key_alias: None,
            data_key_hash: None,
            status: ErrorCode::Ok,
            internal_failure: false,
            message: None,
        })
        .fire::<T>();

        Ok(KeyhouseResponse {
            response: keyhouse::PingPongResponse {
                error_code: ErrorCode::Ok as i32,
                timestamp: request.timestamp,
            },
            spiffe_id: total_spiffe_id,
            error_code: ErrorCode::Ok,
            target_alias: None,
        })
    }
}
