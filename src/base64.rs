#[test]
fn b64_encode_test() {
    let input_text = "This is a testing string.";
    let expected_result = "VGhpcyBpcyBhIHRlc3Rpbmcgc3RyaW5nLg==";

    let encoded_value = encode_b64(input_text);

    assert_eq!(encoded_value, expected_result)
}

#[test]
fn b64url_encode_test() {
    let input_text = "This tests the base64url encoder.";
    let expected_result = "VGhpcyB0ZXN0cyB0aGUgYmFzZTY0dXJsIGVuY29kZXIu";

    let encoded_value = encode_b64url(input_text);

    assert_eq!(encoded_value, expected_result)
}

// TODO: implement decoding

pub fn encode_b64url(input: &str) -> String {
    convert(input, &B64_URL_INDEX_TO_CHAR)
}

pub fn encode_b64(input: &str) -> String {
    convert(input, &B64_INDEX_TO_CHAR)
}

fn convert(input: &str, lookup_table: &[char; 64]) -> String {
    // first we split the input into an array of bytes
    let input_bytes = input.as_bytes();

    let mut result = String::with_capacity(4 * ((input.len() + 2) / 3));

    // we then need to process 3 bytes at a time, using the builtin chunk method.
    // this gives us 24 bits to work with (8 * 3)
    for chunk in input_bytes.chunks(3) {
        // First 6 bits from first byte - always safe as chunk has at least 1 byte
        let b1 = (chunk[0] & 0b11111100) >> 2;
        result.push(lookup_table[b1 as usize]);

        match chunk.len() {
            3 => {
                // All bytes available - do full processing
                let b2 = ((chunk[0] & 0b00000011) << 4) | ((chunk[1] & 0b11110000) >> 4);
                let b3 = ((chunk[1] & 0b00001111) << 2) | ((chunk[2] & 0b11000000) >> 6);
                let b4 = chunk[2] & 0b00111111;

                result.push(lookup_table[b2 as usize]);
                result.push(lookup_table[b3 as usize]);
                result.push(lookup_table[b4 as usize]);
            },
            2 => {
                // Only first two bytes available
                let b2 = ((chunk[0] & 0b00000011) << 4) | ((chunk[1] & 0b11110000) >> 4);
                let b3 = (chunk[1] & 0b00001111) << 2; // No third byte to combine with

                result.push(lookup_table[b2 as usize]);
                result.push(lookup_table[b3 as usize]);
                result.push('=');
            },
            1 => {
                // Only first byte available
                let b2 = (chunk[0] & 0b00000011) << 4; // No second byte to combine with

                result.push(lookup_table[b2 as usize]);
                result.push('=');
                result.push('=');
            },
            _ => unreachable!()
        }
    }

    result
}

const B64_INDEX_TO_CHAR: [char; 64] = [
    // Uppercase Letters (0-25)
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z',

    // Lowercase Letters (26-51)
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z',

    // Digits (52-61)
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',

    // Symbols (62-63)
    '+', '/'
];

const B64_URL_INDEX_TO_CHAR: [char; 64] = [
    // Uppercase Letters (0-25)
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z',

    // Lowercase Letters (26-51)
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z',

    // Digits (52-61)
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',

    // Symbols (62-63)
    '-', '_'
];
