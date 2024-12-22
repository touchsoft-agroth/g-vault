// The first stage of the AES algorithm.

// The S-Box provides AES non-linearity to the cipher, making it resistant to linear and
// differential cryptanalysis. It works in two main mathematical steps:
// 1. Find the multiplicative inverse in the Galois Field GF(2^8)
// 2. Applying an affine transformation over GF(2)

pub fn gen_sbox() -> [u8; 256] {
    let mut sbox = [0u8; 256];

    for i in 0..256 {
        let inverse = gf_inverse(i as u8);
        sbox[i] = affine_transform(inverse);
    }

    sbox
}


// Formula to multiply two numbers in GF(2^8). Uses standard multiplication algorithm, just with
// XOR instead of additions.
fn gf_multiply(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    let mut hi_bit_set;

    for _ in 0..8 {
        if b & 1 == 1 {
            product ^= a;
        }
        hi_bit_set = a & 0x80;
        a <<= 1;
        if hi_bit_set == 0x80 {
            a ^= 0x1b; // AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    product
}

// Function that finds the multiplicative inverse in GF(2^8)
fn gf_inverse(x: u8) -> u8 {
    if x == 0 {
        return 0;
    }

    let mut x_power = x;
    let mut result = 1;

    // Fermat's Little Theorem: a^254 = a^(-1) mod p in GF(2^8)
    // Therefore, we need 7 multiplications to compute x^254
    for _ in 0..7 {
        result = gf_multiply(result, x_power);
        x_power = gf_multiply(x_power, x_power)
    }

    result
}

fn affine_transform(x: u8) -> u8 {
    let mut result = 0;
    let c = 0x64; // The constant vector used in AES

    for i in 0..8 {
        let bit = ((x >> i) & 1)
                ^ ((x >> ((i + 1) % 8)) & 1)
                ^ ((x >> ((i + 2) % 8)) & 1)
                ^ ((x >> ((i + 3) % 8)) & 1)
                ^ ((x >> ((i + 4) % 8)) & 1);
        result |= bit << i;
    }

    result ^= c;
    result
}

#[test]
fn test_sbox_known_values() {
    let sbox = generate_sbox();
    // Test some known values from the AES specification
    assert_eq!(sbox[0x00], 0x63);
    assert_eq!(sbox[0x01], 0x7c);
    assert_eq!(sbox[0x53], 0xed);
    assert_eq!(sbox[0x7f], 0x4c);
    assert_eq!(sbox[0xff], 0x16);
}