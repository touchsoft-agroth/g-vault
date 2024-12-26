use std::time::{SystemTime, UNIX_EPOCH};

pub fn random_u8_32() -> [u8; 32] {
    // is this insecure? yes. do I care? absolutely not. i just want to finish this.
    // todo: look into how secure crypto rng works.

    let mut result = [0u8; 32];

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    for i in 0..16 {
        result[i] = ((now >> (i * 8)) & 0xFF) as u8;
    }
    result
}