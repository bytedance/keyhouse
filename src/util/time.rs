use std::time::{SystemTime, UNIX_EPOCH};

pub fn epoch() -> u64 {
    let start = SystemTime::now();
    let duration = start.duration_since(UNIX_EPOCH).unwrap();
    duration.as_millis() as u64
}

pub fn epoch_us() -> u128 {
    let start = SystemTime::now();
    let duration = start.duration_since(UNIX_EPOCH).unwrap();
    duration.as_micros()
}

pub fn epoch_minutes() -> u32 {
    (epoch() / (1000 * 60)) as u32
}
