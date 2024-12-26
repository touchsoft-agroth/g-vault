pub fn field_add(a: &[i64; 16], b: &[i64; 16]) -> [i64; 16] {
    let mut result = [0i64; 16];

    for i in 0..16 {
        result[i] = a[i] + b[i];
    };

    result
}

pub fn field_sub(a: &[i64; 16], b: &[i64; 16]) -> [i64; 16] {
    let mut result = [0i64; 16];

    for i in 0..16 {
        result[i] = a[i] - b[i];
    };

    result
}

pub fn field_mul(a: &[i64; 16], b: &[i64; 16]) -> [i64; 16] {
    let mut result = [0i64; 16];
    let mut product = [0i64; 31];

    for i in 0..16 {
        for j in 0..16 {
            product[i+j] += a[i] * b[j];
        }
    }

    for i in 0..15 {
        product[i] += 38 * product[i + 16];
    };

    for i in 0..16 {
        result[i] = product[i];
    };

    carry25519(&mut result);
    carry25519(&mut result);

    result
}

pub fn field_inverse(fe: &[i64; 16]) -> [i64; 16] {
    let mut result = fe.clone();

    for i in (0..254).rev() {
        result = field_mul(&result, &result);
        if i != 2 && i != 4 {
            result = field_mul(&result, fe);
        }
    };

    result
}

pub fn swap25519(a: &mut [i64; 16], b: &mut [i64; 16], bit: i64) {
    let mut t: i64;
    let c: i64 = !(bit - 1);
    for i in 0..16 {
        t = c & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

pub fn pack25519(fe: &[i64; 16]) -> [u8; 32] {
    let mut carry;
    let mut t = fe.clone();
    let mut m = [0i64; 16];
    let mut result = [0u8; 32];

    carry25519(&mut t);
    carry25519(&mut t);
    carry25519(&mut t);

    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        carry = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        swap25519(&mut t, &mut m, 1 - carry);
    };

    for i in 0..16 {
        result[2*i] = (t[i] & 0xff) as u8;
        result[2*i + 1] = (t[i] >> 8) as u8;
    };

    result
}

pub fn unpack25519(input: &[u8; 32]) -> [i64; 16] {
    let mut result = [0i64; 16];

    for i in 0..16 {
        result[i] = input[2*i] as i64 + (((input[2*i + 1] as i64) << 8))
    };
    result[15] &= 0x7fff;

    result
}

fn carry25519(fe: &mut [i64; 16]) {
    let mut carry;
    for i in 0..16 {
        carry = fe[i] >> 16;
        fe[i] -= carry << 16;
        if i < 15 {
            fe[i + 1] += carry;
        } else {
            fe[0] += 38 * carry;
        }
    }
}