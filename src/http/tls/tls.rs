use super::key_generation::gen_private_key;

pub fn do_tls() {
    // step 1. parse the handshake header
    // step 2. generate random private key
    let private_key = gen_private_key();
}

struct Record {
    header: Header,
    fragment: Fragment
}

fn parse_complete_record(buffer: &[u8]) -> Result<Record, ()>{
    if buffer.len() < 5 {
        return Err(());
    };

    let header = parse_header(&buffer[0..5])?;
    if buffer.len() < 5 + header.length as usize {
        return Err(());
    };

    let fragment: Fragment = match header.content_type {
        22 => {
            parse_handshake(&buffer[5..5 + header.length as usize])?
        },
        _ => panic!()
    };

    let record = Record {
        header,
        fragment
    };

    Ok(record)
}


enum Fragment {
    Handshake(HandshakeHeader, HandshakeBody)
}

struct HandshakeHeader {
    handshake_type: u8,
    length: u32, // note: length is only 24 bits (3 bytes)
}

struct HandshakeBody {
    protocol_version: u16,
    random: [u8; 32], // 4 bytes timestamp + 28 bytes random
    session_id: Vec<u8>,
    cipher_suites: Vec<u16>,
    compression_methods: Vec<u8>,
    extensions: Vec<HandshakeExtension>
}

struct HandshakeExtension {
    extension_type: u16,
    extension_length: u16,
    extension_data: Vec<u8>
}

fn parse_handshake(buffer: &[u8]) -> Result<Fragment, ()> {
    let header = parse_handshake_header(buffer);
    // if buffer.len() < 4 + header.length as usize {
    //     return Err(());
    // }

    let body = parse_handshake_body(&buffer[4..buffer.len()]);

    Ok(Fragment::Handshake(header, body))
}

fn parse_handshake_header(buffer: &[u8]) -> HandshakeHeader {
    let handshake_type = buffer[0];
    let length = {
        let b1 = buffer[1] as u32;
        let b2 = buffer[2] as u32;
        let b3 = buffer[3] as u32;

        (b1 << 16) | (b2 << 8) | b3
    };

    HandshakeHeader {
        handshake_type,
        length
    }
}

fn parse_handshake_body(buffer: &[u8]) -> HandshakeBody {
    let mut position = 0;

    let protocol_version = {
        ((buffer[position] as u16) << 8) | (buffer[position + 1] as u16)
    };
    position += 2;

    let mut random: [u8; 32] = [0u8; 32];
    for i in 0..32 {
        random[i] = buffer[position + i];
    };
    position += 32;

    let session_id_length = buffer[position] as usize;
    position += 1;

    let mut session_id: Vec<u8> = Vec::with_capacity(session_id_length);
    for _ in 0..session_id_length {
        session_id.push(buffer[position]);
        position += 1;
    };

    let cipher_suites_length = {
        ((buffer[position] as u16) << 8) | (buffer[position + 1] as u16)
    } as usize;
    position += 2;

    let mut cipher_suites: Vec<u16> = Vec::with_capacity(cipher_suites_length);
    for _ in 0..cipher_suites_length / 2 {
        let cipher = {
            ((buffer[position] as u16) << 8) | (buffer[position + 1] as u16)
        };

        cipher_suites.push(cipher);
        position += 2;
    };

    let compression_methods_length = buffer[position] as usize;
    position += 1;

    let mut compression_methods: Vec<u8> = Vec::with_capacity(compression_methods_length);
    for _ in 0..compression_methods_length {
        compression_methods.push(buffer[position]);
        position += 1;
    };

    let extensions_length = {
        ((buffer[position] as u16) << 8) | (buffer[position + 1] as u16)
    } as usize;
    position += 2;

    let mut extensions: Vec<HandshakeExtension> = Vec::with_capacity(extensions_length);
    let extensions_start_position = position;
    while position < extensions_start_position + extensions_length
    {
        let extension_type = {
            let b1 = buffer[position] as u16;
            let b2 = buffer[position + 1] as u16;
            (b1 << 8) | b2
        } ;
        position += 2;

        let extension_length = {
            let b1 = buffer[position] as u16;
            let b2 = buffer[position + 1] as u16;
            (b1 << 8) | b2
        };
        position += 2;

        let mut extension_data: Vec<u8> = Vec::with_capacity(extension_length as usize);
        for _ in 0..extension_length as usize {
            extension_data.push(buffer[position]);
            position += 1;
        }

        let extension = HandshakeExtension {
            extension_type,
            extension_length,
            extension_data
        };

        extensions.push(extension);
    }

    HandshakeBody {
        protocol_version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        extensions
    }
}

#[test]
fn test_handshake_parsing() {
    let test_data = [
        // -- record header --
        0x16, // handshake record (16)
        0x03, 0x01, // protocol 3,1 / TLS 1.0
        0x00, 0xf8, // 0xF8 (248) length of message


        // -- handshake header --
        0x01, // message type 0x01 (client hello)
        0x00, 0x00, 0xf4, // 0xF4 (244) hello data length


        // -- client version --
        0x03, 0x03, // protocol 3,3 / TLS 1.2

        // -- client random --
        0x00, 0x01, 0x02, 0x03, // timestamp

        // actual random numbers
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,

        // -- session id --
        0x20, // 32 bytes of session id follows

        // fake session id
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb,
        0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,

        // -- cipher suits --
        0x00, 0x08, // 8 bytes of cipher data
        0x13, 0x02, // assigned value for TLS_AES_256_GCM_SHA384
        0x13, 0x03, // assigned value for TLS_CHACHA20_POLY1305_SHA256
        0x13, 0x01, // assigned value for TLS_AES_128_GCM_SHA256
        0x00, 0xff, // assigned value for TLS_EMPTY_RENEGOTIATION_INFO_SCSV

        // -- compression methods --
        0x01, // 1 byte of compression methods
        0x00, // null

        // -- extensions length
        0x00, 0xa3, // 0xA3 (163) bytes of data

        // -- extension server name --
        0x00, 0x00, // assigned value for server name
        0x00, 0x18, // 0x18 (24) bytes of "server name" extension data follows
        0x00, 0x16, // 0x16 (22) bytes of first (and only) list entry follows
        0x00, // list entry is type 0x00 "DNS hostname"
        0x00, 0x13, // 0x13 (19) bytes of hostname follows
        0x65, 0x78, 0x61,

        // "example.ulfheim.net"
        0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d,
        0x2e, 0x6e, 0x65, 0x74,

        // -- extension ec point formats --
        0x00, 0x0b, // assigned value for "ec point formats"
        0x00, 0x04, // 4 bytes follow
        0x03, // 3 bytes of format types
        0x00, 0x01, 0x02, // uncompressed, ansiX962_compressed_prime, ansiX962_compressed_char2

        // -- extension supported groups --
        0x00, 0x0a, // assigned value for "supported groups"
        0x00, 0x16, // 22 bytes follow
        0x00, 0x14, // 20 bytes in curves list
        0x00, 0x1d, // x25519
        0x00, 0x17, // secp256r1
        0x00, 0x1e, // x448
        0x00, 0x19, // secp521r1
        0x00, 0x18, // secp384r1
        0x01, 0x00, // ffdhe2048
        0x01, 0x01, // ffdhe3072
        0x01, 0x02, // ffdhe4096
        0x01, 0x03, // ffdhe6144
        0x01, 0x04, // ffdhe8192

        // -- extension session ticket --
        0x00, 0x23, // assigned value for "Session Ticket"
        0x00, 0x00, // 0 bytes follow

        // -- extension encrypt-then-mac --
        0x00, 0x16, // assigned value for "Encrypt Then MAC"
        0x00, 0x00, // 0 bytes follow

        // -- extension extended master secret --
        0x00, 0x17, // assigned value for "Extended Master Secret"
        0x00, 0x00, // 0 bytes follow

        // -- extension signature algorithms --
        0x00, 0x0d, // assigned value for "Signature Algorithms"
        0x00, 0x1e, // 30 bytes follow
        0x00, 0x1c, // 28 bytes in algorithm list
        0x04, 0x03, // ECDSA-SECP256r1-SHA256
        0x05, 0x03, // ECDSA-SECP384r1-SHA384
        0x06, 0x03, // ECDSA-SECP521r1-SHA512
        0x08, 0x07, // ED25519
        0x08, 0x08, // ED448
        0x08, 0x09, // RSA-PSS-PSS-SHA256
        0x08, 0x0a, // RSA-PSS-PSS-SHA384
        0x08, 0x0b, // RSA-PSS-PSS-SHA512
        0x08, 0x04, // RSA-PSS-RSAE-SHA256
        0x08, 0x05, // RSA-PSS-RSAE-SHA384
        0x08, 0x06, // RSA-PSS-RSAE-SHA512
        0x04, 0x01, // RSA-PKCS1-SHA256
        0x05, 0x01, // RSA-PKCS1-SHA384
        0x06, 0x01, // RSA-PKCS1-SHA512

        // -- extension supported versions --
        0x00, 0x2b, // assigned value for "Supported Versions"
        0x00, 0x03, // 3 bytes follow
        0x02, // 2 bytes of versions follow
        0x03, 0x04, // TLS 1.3

        // -- extension PSK key exchange modes --
        0x00, 0x2d, // assigned value for "PSK Key Exchange Modes"
        0x00, 0x02, // 2 bytes follow
        0x01, // 1 byte of modes
        0x01, // PSK with (EC)DHE key establishment

        // -- extension key share --
        0x00, 0x33, // assigned value for "Key Share"
        0x00, 0x26, // 38 bytes follow
        0x00, 0x24, // 36 bytes of key share data
        0x00, 0x1d, // x25519 curve
        0x00, 0x20, // 32 bytes of public key follows

        // public key bytes
        0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1,
        0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38,
        0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75,
        0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54
    ];

    let record = parse_complete_record(&test_data).unwrap();
    assert_eq!(true, true);
}

struct Header {
    pub content_type: u8,
    pub protocol_version: u16,
    pub length: u16
}

pub fn parse_header(buffer: &[u8]) -> Result<Header, ()> {
    let message_type = buffer[0];

    let preferred_tls_version = {
        let b1 = buffer[1];
        let b2 = buffer[2];

        ((b1 as u16) << 8) | (b2 as u16)
    };

    let length = {
        let b1 = buffer[3];
        let b2 = buffer[4];

        ((b1 as u16) << 8) | (b2 as u16)
    };

    Ok(Header {
        content_type: message_type,
        protocol_version: preferred_tls_version,
        length
    })
}


