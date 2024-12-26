use super::field_arithmetic::*;

pub struct KeyPair {
    pub public: Key,
    pub private: Key
}

impl KeyPair {
    pub fn generate() -> Self {
        let keypair = generate_keypair();
        Self {
            public: Key {
                value: keypair.1
            },
            private: Key {
                value: keypair.0
            }
        }
    }
}

pub struct Key {
    value: [u8; 32]
}

impl Key {
    pub fn create_shared(public: &Key, private: &Key) -> Self {
        Self {
            value: x25519(&private.value, &public.value)
        }
    }

    pub fn compare(&self, other: &Key) -> bool {
        self.value == other.value
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.value.to_vec()
    }
}

static NINE: [u8; 32] = [9; 32];

fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut private_key = crate::utils::random::random_u8_32();
    let mut public_key = scalar_multiply(&private_key, &NINE);
    (private_key, public_key)
}

fn x25519(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    scalar_multiply(private_key, public_key)
}

const _121665: [i64; 16] = {
    let mut arr = [0; 16];
    arr[0] = 0xDB41;
    arr[1] = 1;
    arr
};

fn scalar_multiply(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut bit = 0i64;
    let mut a = [0i64; 16];
    let mut b = [0i64; 16];
    let mut c = [0i64; 16];
    let mut d = [0i64; 16];
    let mut e = [0i64; 16];
    let mut f = [0i64; 16];
    let mut x = [0i64; 16];

    let mut clamped = scalar.clone();
    clamped[0] &= 0xf8;
    clamped[31] = (clamped[31] & 0x7f) | 0x40;

    x = unpack25519(point);
    for i in 0..16 {
        b[i] = x[i];
    };
    a[0] = 1;
    d[0] = 1;

    for i in (0..255).rev() {
        bit = ((clamped[i >> 3] >> (i & 7)) & 1) as i64;
        swap25519(&mut a, &mut b, bit);
        swap25519(&mut c, &mut d, bit);
        e = field_add(&a, &c);
        a = field_sub(&a, &c);
        c = field_add(&b, &d);
        b = field_sub(&b, &d);
        d = field_mul(&e, &e);
        f = field_mul(&a, &a);
        a = field_mul(&c, &a);
        c = field_mul(&b, &e);
        e = field_add(&a, &c);
        a = field_sub(&a, &c);
        b = field_mul(&a, &a);
        c = field_sub(&d, &f);
        a = field_mul(&c, &_121665);
        a = field_add(&a, &d);
        c = field_mul(&c, &a);
        a = field_mul(&d, &f);
        d = field_mul(&b, &x);
        b = field_mul(&e, &e);
        swap25519(&mut a, &mut b, bit);
        swap25519(&mut c, &mut d, bit);
    };

    c = field_inverse(&c);
    a = field_mul(&a, &c);
    pack25519(&a)
}