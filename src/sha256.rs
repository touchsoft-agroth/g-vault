pub fn hash(input: &[u8]) -> [u8; 32] {
    let message = preprocess_message(input);

    // Message scheduling on all 512-bit blocks in the message
    let mut hash_values = INITIAL_HASH;
    for chunk in message.chunks(64) {
        let mut words: [u32; 64] = [0;64];
        // Get W0..W15
        for i in 0..16 {
            let start = i * 4;
            let bytes = [chunk[start], chunk[start+1], chunk[start+2], chunk[start+3]];
            words[i] = u32::from_be_bytes(bytes);
        }

        for i in 16..64 {
            let w = small_sigma1(words[i-2])
                .wrapping_add(words[i-7])
                .wrapping_add(small_sigma0(words[i-15]))
                .wrapping_add(words[i-16]);

            words[i] = w;
        }

        let mut a = hash_values[0];
        let mut b = hash_values[1];
        let mut c = hash_values[2];
        let mut d = hash_values[3];
        let mut e = hash_values[4];
        let mut f = hash_values[5];
        let mut g = hash_values[6];
        let mut h = hash_values[7];

        for i in 0..64 {
            let round = K[i];
            let t1 = h.wrapping_add(large_sigma1(e))
                .wrapping_add(calculate_choose(e, f, g))
                .wrapping_add(round)
                .wrapping_add(words[i]);
            let t2 = large_sigma0(a).wrapping_add(calculate_majority(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        hash_values[0] = hash_values[0].wrapping_add(a);
        hash_values[1] = hash_values[1].wrapping_add(b);
        hash_values[2] = hash_values[2].wrapping_add(c);
        hash_values[3] = hash_values[3].wrapping_add(d);
        hash_values[4] = hash_values[4].wrapping_add(e);
        hash_values[5] = hash_values[5].wrapping_add(f);
        hash_values[6] = hash_values[6].wrapping_add(g);
        hash_values[7] = hash_values[7].wrapping_add(h);
    };
    let mut final_hash = [0u8; 32];
    for (i, &value) in hash_values.iter().enumerate() {
        // Convert each 32-bit hash value into 4 bytes in big-endian order
        let bytes = value.to_be_bytes();
        // Copy these 4 bytes into the appropriate position in our final array
        final_hash[i*4..(i+1)*4].copy_from_slice(&bytes);
    }

    final_hash
}

// The initialization values (IV) for the SHA-256 algorithm. Consists of the fractional
// parts of the square roots of the first 8 primes (2..19)
const INITIAL_HASH: [u32; 8] = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
];

// The first 32 bits of the cube roots of the first 64 primes (22..311)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn calculate_choose(e: u32, f: u32, g: u32) -> u32 {
    // for each bit position, use e to determine if the bit from f or g should be kept.
    // if e = 1, use f bit
    // else use g bit
    (e & f) ^ ((!e) & g)
}

fn calculate_majority(a: u32, b: u32, c: u32) -> u32 {
    // converts bits that are 1 across 2 of 3 bytes into 1, else it becomes 0
    (a & b) ^ (a & c) ^ (b & c)
}

fn large_sigma0(a: u32) -> u32 {
    let r1 = a.rotate_right(2);
    let r2 = a.rotate_right(13);
    let r3 = a.rotate_right(22);

    r1 ^ r2 ^ r3
}

fn large_sigma1(e: u32) -> u32 {
    let r1 = e.rotate_right(6);
    let r2 = e.rotate_right(11);
    let r3 = e.rotate_right(25);

    r1 ^ r2 ^ r3
}

fn small_sigma0(i1: u32) -> u32 {
    let r1 = i1.rotate_right(7);
    let r2 = i1.rotate_right(18);
    let s = i1 >> 3;

    r1 ^ r2 ^ s
}

fn small_sigma1(i1: u32) -> u32 {
    let r1 = i1.rotate_right(17);
    let r2 = i1.rotate_right(19);
    let s = i1 >> 10;

    r1 ^ r2 ^ s
}

fn preprocess_message(input_message: &[u8]) -> Vec<u8> {
    let message_length: u64 = (input_message.len() as u64) * 8;

    let mut message: Vec<u8> = input_message.to_vec();
    // Start by adding the '1' bit after the message.
    // Adding 0x80 is the same as adding 1000000 in binary
    message.push(0x80);

    // Now, we have to keep adding '0' bits until the total length of the message is a multiple
    // of 512 bits, accounting for the 8 bytes at the end needed for the message size (64 bits)
    while (message.len() + 8) % 64 != 0 {
        message.push(0x00);
    }

    // Now we add the total length of the original message to the end.
    let length_bits = message_length.to_be_bytes();
    message.extend_from_slice(&length_bits);

    message
}

#[test]
pub fn hash_test() {
    let input = "the quick brown fox jumps over the lazy dog";

    // 05c6e08f1d9fdafa03147fcb8f82f124c76d2f70e3d989dc8aadb5e7d7450bec
    let expected_output: [u8; 32] = [
        0x05, 0xc6, 0xe0, 0x8f, // 05c6e08f
        0x1d, 0x9f, 0xda, 0xfa, // 1d9fdafa
        0x03, 0x14, 0x7f, 0xcb, // 03147fcb
        0x8f, 0x82, 0xf1, 0x24, // 8f82f124
        0xc7, 0x6d, 0x2f, 0x70, // c76d2f70
        0xe3, 0xd9, 0x89, 0xdc, // e3d989dc
        0x8a, 0xad, 0xb5, 0xe7, // 8aadb5e7
        0xd7, 0x45, 0x0b, 0xec  // d7450bec"
    ];

    let hashed_output = hash(input.as_bytes());
    assert_eq!(hashed_output, expected_output);
}