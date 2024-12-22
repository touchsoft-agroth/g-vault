use super::sbox::gen_sbox;
use super::key_schedule::KeySchedule;
use super::state::State;

pub struct AES {
    sbox: [u8; 256],
    key_schedule: KeySchedule
}

impl AES {
    pub fn new(key: &[u8]) -> Self {
        let sbox = gen_sbox();
        let key_schedule = KeySchedule::new(key, &sbox);

        Self {
            sbox,
            key_schedule,
        }
    }

    // Encrypts arbitrary length data using CBC mode.
    // Returns the ciphertext including the IB
    pub fn encrypt(&self, plaintext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        let padded_plaintext = pad_data(plaintext);
        let mut ciphertext = Vec::with_capacity(16 + padded_plaintext.len());

        ciphertext.extend_from_slice(iv);

        let mut previous_block = iv.to_vec();

        for chunk in padded_plaintext.chunks(16) {
            let mut block = Vec::with_capacity(16);

            for (a, b) in chunk.iter().zip(previous_block.iter()) {
                block.push(a ^ b);
            }

            let encrypted_block = self.encrypt_block(&block);

            ciphertext.extend_from_slice(&encrypted_block);
            previous_block = encrypted_block;
        };

        ciphertext
    }

    fn encrypt_block(&self, input: &[u8]) -> Vec<u8> {
        let mut state = State::new(input);

        // initial round - just key addition
        state.add_round_key(self.key_schedule.get_round_key(0));

        // main rounds
        for round in 1..10 {
            state.sub_bytes(&self.sbox);
            state.shift_rows();
            state.mix_columns();
            state.add_round_key(self.key_schedule.get_round_key(round));
        }

        // final round - no MixColumns
        state.sub_bytes(&self.sbox);
        state.shift_rows();
        state.add_round_key(self.key_schedule.get_round_key(10));


        state.as_bytes()
    }
}

// PKCS7 padding, which adds bytes to ensure that the data length is a multiple of the
// block size.
fn pad_data(data: &[u8]) -> Vec<u8> {
    let block_size = 16;
    let padding_length = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + padding_length);

    padded.extend_from_slice(data);

    for _ in 0..padding_length {
        padded.push(padding_length as u8);
    };

    padded
}