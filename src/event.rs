use crate::{keyhouse::ErrorCode, prelude::*};
use sentry::protocol;
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
#[serde(tag = "type")]
pub enum LogEvent {
    InternalLogEvent(InternalLogEvent),
    DataLogEvent(DataLogEvent),
    ControlLogEvent(ControlLogEvent),
}

#[derive(Debug, Serialize, Clone)]
pub enum DataRequestType {
    EncodeDataKey,
    DecodeDataKey,
    PingPong,
    GetSecret,
    GetSecrets,
    StoreSecret,
    GetLegacyKey,
    Unknown,
}

impl Default for DataRequestType {
    fn default() -> DataRequestType {
        DataRequestType::Unknown
    }
}

impl DataRequestType {
    pub fn name(&self) -> &'static str {
        use DataRequestType::*;
        match self {
            EncodeDataKey => "EncodeDataKey",
            DecodeDataKey => "DecodeDataKey",
            PingPong => "PingPong",
            GetSecret => "GetSecret",
            GetSecrets => "GetSecrets",
            StoreSecret => "StoreSecret",
            GetLegacyKey => "GetLegacyKey",
            Unknown => "Unknown",
        }
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Default, Clone)]
pub struct DataLogEvent {
    pub occurred_at: u64,
    pub request_type: DataRequestType,
    pub spiffe_id: Option<String>,
    pub token: Option<String>,
    pub auth_service: Option<String>,
    pub auth_user: Option<String>,
    pub ip: String,
    pub key_id: Option<u32>,
    pub key_alias: Option<String>,
    pub data_key_hash: Option<String>,
    pub status: ErrorCode,
    pub internal_failure: bool,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub enum InternalRequestType {
    ReissueCustomerKey,
    ReissueIntermediateKey,
    Unknown,
}

impl Default for InternalRequestType {
    fn default() -> InternalRequestType {
        InternalRequestType::Unknown
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Default, Clone)]
pub struct InternalLogEvent {
    pub occurred_at: u64,
    pub request_type: InternalRequestType,
    pub key_id: Option<u32>,
    pub key_alias: Option<String>,
    pub success: bool,
    pub message: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Default, Clone)]
pub struct ControlLogEvent {
    pub occurred_at: u64,
    pub path: String,
    pub username: Option<String>,
    pub ip: String,
    pub xff_ip: Option<String>,
    pub log_id: Option<String>,
    pub key_alias: Option<String>,
    pub keyring_alias: Option<String>,
    pub secret_alias: Option<String>,
    pub status: u16,
    pub message: Option<String>,
}

impl LogEvent {
    pub fn fire<T: KeyhouseImpl + 'static>(&self) {
        T::KeyhouseExt::emit_event(self);
        let encoded = serde_json::to_string(&self)
            .unwrap_or_else(|e| format!("serialization error in LogEvent.fire: {:?}", e));

        if match self {
            LogEvent::InternalLogEvent(e) => e.success,
            LogEvent::DataLogEvent(e) => !e.internal_failure,
            LogEvent::ControlLogEvent(e) => e.status < 500,
        } {
            info!("{}", encoded)
        } else {
            error!("{}", encoded)
        }
    }
}

pub fn sentry_error(message: String) {
    error!("{}", message);
    sentry::capture_event(protocol::Event {
        message: Some(message),
        level: protocol::Level::Error,
        ..Default::default()
    });
}

#[macro_export]
macro_rules! sentry_error {
    ($($arg:tt)*) => { $crate::event::sentry_error(format!($($arg)*)) }
}
