use crate::util;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Keyring {
    pub alias: String,
    pub created_at: u64,
    pub description: String,
}

impl Keyring {
    pub fn new_base(alias: String) -> Keyring {
        Keyring {
            alias,
            created_at: util::epoch(),
            description: "".to_string(),
        }
    }
}

pub fn split_alias(alias: &str) -> (&str, &str) {
    match alias.find('/') {
        None => (alias, ""),
        Some(i) => (&alias[0..i], &alias[i + 1..]),
    }
}

pub fn split_last_alias(alias: &str) -> (&str, &str) {
    match alias.rfind('/') {
        None => (alias, ""),
        Some(i) => (&alias[0..i], &alias[i + 1..]),
    }
}
