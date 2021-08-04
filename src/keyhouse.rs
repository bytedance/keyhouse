use serde::Serialize;
use zeroize::Zeroize;

tonic::include_proto!("kms");

#[derive(Serialize, Clone, Copy, Debug, PartialEq)]
pub enum ErrorCode {
    Ok = 0, // Operation OK or signature verified
    Unauthorized = 1,
    UnknownAlias = 2,
    UnknownKey = 3,
    BadPayload = 4,
    Forbidden = 5,
    Unknown = 255,
}

impl ErrorCode {
    pub fn from_primitive(primitive: usize) -> Self {
        match primitive {
            0 => ErrorCode::Ok,
            1 => ErrorCode::Unauthorized,
            2 => ErrorCode::UnknownAlias,
            3 => ErrorCode::UnknownKey,
            4 => ErrorCode::BadPayload,
            5 => ErrorCode::Forbidden,
            _ => ErrorCode::Unknown,
        }
    }
}

impl ToString for ErrorCode {
    fn to_string(&self) -> String {
        use ErrorCode::*;
        match self {
            Ok => "Ok",
            Unauthorized => "Unauthorized",
            UnknownAlias => "UnknownAlias",
            UnknownKey => "UnknownKey",
            BadPayload => "BadPayload",
            Forbidden => "Forbidden",
            Unknown => "Unknown",
        }
        .to_string()
    }
}

impl Default for ErrorCode {
    fn default() -> ErrorCode {
        ErrorCode::Ok
    }
}

impl Drop for StoreSecretRequest {
    fn drop(&mut self) {
        self.token.zeroize();
        self.alias.zeroize();
        self.secret.zeroize();
    }
}
