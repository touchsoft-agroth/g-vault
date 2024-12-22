// The second stage of the AES algorithm, Key expansion (or key scheduling).

// Transforms the initial encryption key into a series of round keys that will
// be used in each round of the encryption process.


pub struct KeySchedule {
    round_keys: Vec<u8>,
    rounds: usize
}

impl KeySchedule {
    pub fn new(key: &[u8], sbox: &[u8;256]) -> Self {
        let round_keys = expand_key(key, sbox);
        Self {
            round_keys,
            rounds: 10 // 10 rounds for AES-128, +1 for initial key for total of 11
        }
    }

    pub fn get_round_key(&self, round: usize) -> &[u8] {
        let start = round * 16;
        &self.round_keys[start..start + 16]
    }
}

fn expand_key(key: &[u8], sbox: &[u8;256]) -> Vec<u8> {
    let rounds = 10; // For AES-128
    let round_key_size = 16; // 128 bits = 16 bytes
    let total_size = round_key_size * (rounds + 1);
    let mut expanded_key = vec![0u8;total_size];
    let rcon = generate_rcon();

    // Copy the original key into the first round key
    expanded_key[..16].copy_from_slice(&key[..16]);

    // Now generate the remaining round keys
    let mut i = 1;
    let mut pos = 16;

    while pos < total_size {
        let mut temp = [
            expanded_key[pos - 4],
            expanded_key[pos - 3],
            expanded_key[pos - 2],
            expanded_key[pos - 1],
        ];

        if pos % 16 == 0 {
            temp = rot_word(temp);
            temp = sub_word(temp, sbox);
            temp[0] ^= rcon[i - 1];
            i += 1;
        }

        // XOR with bytes 16 positions earlier
        for j in 0..4 {
            expanded_key[pos + j] = expanded_key[pos - 16 + j] ^ temp[j];
        }

        pos += 4;
    }

    expanded_key
}

fn generate_rcon() -> [u8;10] {
    let mut rcon = [0u8;10];
    let mut x = 1;

    for i in 0..10 {
        rcon[i] = x;
        // Multiply it by 2 in GF(2^8)
        x = (x << 1) ^ ((x >> 7) & 0x1b);
    }

    rcon
}

// Performs a cyclic permutation on a 4-byte word
fn rot_word(word: [u8;4]) -> [u8;4] {
    [word[1], word[2], word[3], word[0]]
}

fn sub_word(word: [u8;4], sbox: &[u8; 256]) -> [u8;4] {
    let mut result = [0u8;4];
    for i in 0..4 {
        result[i] = sbox[word[i] as usize]
    }
    result
}