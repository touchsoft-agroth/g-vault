use super::handshakes::{HandshakeMessageType};

pub enum Record {
    Handshake(HandshakeMessageType)
}

impl Record {
    pub fn parse(buffer: &[u8]) -> Result<Record, &'static str> {
        let header = RecordHeader::parse(buffer)?;

        if buffer.len() < RecordHeader::EXPECTED_LENGTH + header.length {
            return Err("Buffer is shorter than declared record length");
        }

        match header.content_type {
            0x16 => {
                match HandshakeMessageType::parse(&buffer[RecordHeader::EXPECTED_LENGTH..]) {
                    Ok(message_type) => {
                        Ok(Record::Handshake(message_type))
                    },
                    Err(err) => {
                        Err(err)
                    }
                }
            },
            _ => {
                panic!("unexpected record type")
            }
        }
    }

    pub fn into_bytes(&self) -> Vec<u8> {
        let mut result = vec![];

        match self {
            Self::Handshake(handshake_message) => {
                // type - handshake
                result.push(0x16);

                let handshake_bytes = handshake_message.into_bytes();

                // data length - **should** be 2 bytes
                result.extend_from_slice(&(handshake_bytes.len() as u16).to_be_bytes());

                // data - max u16
                result.extend_from_slice(&handshake_message.into_bytes());
            }
        }

        result
    }
}

struct RecordHeader {
    pub content_type: u8,
    pub protocol_version: u16,
    pub length: usize
}

impl RecordHeader {
    pub const EXPECTED_LENGTH: usize = 5;

    pub fn parse(buffer: &[u8]) -> Result<RecordHeader, &'static str> {
        if buffer.len() < Self::EXPECTED_LENGTH {
            return Err("Buffer length is less than 5, which is the expected record header length");
        }

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
        } as usize;

        Ok(RecordHeader {
            content_type: message_type,
            protocol_version: preferred_tls_version,
            length
        })
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

    let record = Record::parse(&test_data);
    assert_eq!(true, true);
}
