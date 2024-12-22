// Represents the current state of the AES encryption process.
// Maintained as a 4x4 matrix of bytes per the AES specification.
// Data is stored in column-major order to match AESs mathematical structure.
pub struct State {
    data: [[u8;4];4]
}

impl State {
    pub fn new(input: &[u8]) -> Self {
        let mut data = [[0u8;4];4];

        // Fill the matrix column by column
        for col in 0..4 {
            for row in 0..4 {
                data[row][col] = input[col * 4 + row];
            }
        }

        Self {
            data
        }
    }

    // Applies the AddRoundKey transformation to the current state.
    //
    // Transformation applies a byte-by-byte XOR between the state and the round key.
    // This is the only transformation uses the key material directly.
    pub fn add_round_key(&mut self, round_key: &[u8]) {
        // Convert the round key to matrix format
        let mut key_matrix = [[0u8; 4]; 4];
        for col in 0..4 {
            for row in 0..4 {
                key_matrix[row][col] = round_key[col * 4 + row];
            }
        }

        // XOR the state matrix with the key matrix
        for col in 0..4 {
            for row in 0..4 {
                self.data[row][col] ^= key_matrix[row][col]
            }
        }
    }


    // Applies the SubBytes transformation to the current state.
    //
    // This transformation processes each byte of the state matrix independently,
    // replacing it with its corresponding value from the s-box.
    // Provides non-linearity to the cipher.
    pub fn sub_bytes(&mut self, sbox: &[u8; 256]) {
        for row in 0..4 {
            for col in 0..4 {
                self.data[row][col] = sbox[self.data[row][col] as usize]
            }
        }
    }

    // Applies the ShiftRows transformation to the current state.
    //
    // Cyclically shifts each row of the state matrix to the left:
    // - Row 0: No shift
    // - Row 1: Shift left by 1
    // - Row 2: Shift left by 2
    // - Row 3: Shift left by 3
    //
    // Ensures each column in the output state contains different bytes from
    // different columns of the input state, providing diffusion across columns.
    pub fn shift_rows(&mut self) {
        let original = self.data;

        for row in 0..4 {
            for col in 0..4 {
                let shifted_col = (col + row) % 4;
                self.data[row][col] = original[row][shifted_col];
            }
        }
    }

    // Applies the MixColumns transformation to the current state.
    //
    // This transformation treats each column as a four-term polynomial over GF(2^8).
    // Multiplies it with a fixed polynomial c(x) = '03'x^3 + '01'x^2 + '01'x + '02' mod x^4 + 1
    pub fn mix_columns(&mut self) {
        fn multiply_by_2(b: u8) -> u8 {
            let shifted = b << 1;
            if (b & 0x80) != 0 {
                shifted ^ 0x1B
            } else {
                shifted
            }
        }

        fn multiply_by_3(b: u8) -> u8 {
            multiply_by_2(b) ^ b
        }

        for col in 0..4 {
            let original = [
                self.data[0][col],
                self.data[1][col],
                self.data[2][col],
                self.data[3][col],
            ];

            // Apply the matrix multiplication for MixColumns
            self.data[0][col] =
                multiply_by_2(original[0]) ^
                    multiply_by_3(original[1]) ^
                    original[2] ^
                    original[3];

            self.data[1][col] =
                original[0] ^
                    multiply_by_2(original[1]) ^
                    multiply_by_3(original[2]) ^
                    original[3];

            self.data[2][col] =
                original[0] ^
                    original[1] ^
                    multiply_by_2(original[2]) ^
                    multiply_by_3(original[3]);

            self.data[3][col] =
                multiply_by_3(original[0]) ^
                    original[1] ^
                    original[2] ^
                    multiply_by_2(original[3]);
        }
    }

    // Converts the current state back into a vector of bytes.
    //
    // The bytes are extracted from the state matrix in column-major order, so that is matches the
    // original ordering used to create the state.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(16);

        for col in 0..4 {
            for row in 0..4 {
                result.push(self.data[row][col]);
            }
        }

        result
    }
}
