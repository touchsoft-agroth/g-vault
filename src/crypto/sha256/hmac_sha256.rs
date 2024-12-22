use super::sha256;

const OPAD: [u8; 64] = [0x5C; 64];
const IPAD: [u8; 64] = [0x36; 64];

pub fn hash(input: &str, secret_key: &str) -> String {
    let processed_key = process_key(secret_key);
    let message_bytes = input.as_bytes();

    let inner_hash = create_inner_hash(&processed_key, message_bytes);
    let final_bytes = create_outer_hash(&processed_key, &inner_hash);

    bytes_to_hex_string(&final_bytes)
}

fn create_outer_hash(key: &[u8], inner_hash: &[u8]) -> [u8; 32] {
    let mut key_buffer = key.to_vec();
    for i in 0..key_buffer.len() {
        key_buffer[i] = key_buffer[i] ^ OPAD[i];
    }

    let mut final_message = key_buffer;
    final_message.extend_from_slice(inner_hash);

    sha256::hash(&final_message)
}

fn create_inner_hash(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_buffer = key.to_vec();
    for i in 0..key_buffer.len() {
        key_buffer[i] = key_buffer[i] ^ IPAD[i];
    }

    let mut final_message = key_buffer;
    final_message.extend_from_slice(message);

    sha256::hash(&final_message)
}

fn process_key(key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    let mut processed = Vec::with_capacity(64);

    if key_bytes.len() > 64 {
        // Hash the key if it's too long
        let hashed = sha256::hash(key_bytes);
        processed.extend_from_slice(&hashed);
        processed.resize(64, 0);
    } else {
        processed.extend_from_slice(key_bytes);
        processed.resize(64, 0);
    }

    processed
}

fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[test]
pub fn hash_test() {
    let input = "This is a message to encrypt.";
    let secret = "The super secret key for encrypting.";
    let expected_output = "a636e5a1fe12f13a9b967473b1368f40c540761d37a33df2a4d8151f22606c53";

    let hashed_output = hash(input, secret);

    assert_eq!(hashed_output, expected_output);
}