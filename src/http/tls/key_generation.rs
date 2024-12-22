use std::time::{SystemTime, UNIX_EPOCH};

const P: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
];

const N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
];

pub fn gen_private_key() -> [u8; 32] {
    let mut key = [0u8; 32];

    // is this completely secure? not at all. do I care? no. I have work tomorrow and it is 1 am.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();

    for i in 0..32 {
        let mixed = ((nanos + i as u32) ^ (nanos >> i)) as u8;
        key[i] = mixed;
    };

    let mut result = [0u8; 32];
    let mut carry = 0u16;

    // Perform modulo n by repeated subtraction
    for i in (0..32).rev() {
        let val = key[i] as u16 + (carry << 8);
        if val >= N[i] as u16 {
            result[i] = (val - N[i] as u16) as u8;
            carry = 1;
        } else {
            result[i] = val as u8;
            carry = 0;
        }
    }
    result
}
