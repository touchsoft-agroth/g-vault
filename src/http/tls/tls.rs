use std::io::Write;
use std::net::TcpStream;
use crate::crypto::x25519::Key;
use crate::http::tls::extensions::Extension;
use crate::http::tls::handshakes::{ClientHelloData, ServerHelloData};
use crate::utils::formatting::bytes_to_hex;
use super::records::Record;
use super::handshakes::HandshakeMessageType;

pub fn do_tls(buffer: &[u8], stream: &mut TcpStream) {
    // step 1. Client sends the ClientHello. Parse the client hello.
    if let Record::Handshake(handshake_message) = Record::parse(buffer).unwrap() {
        if let HandshakeMessageType::ClientHello(client_hello_data) = handshake_message {

            // step 2. Build and respond with ServerHello.
            let (server_hello, server_private_key) = build_server_hello(&client_hello_data);
            let hello_bytes = server_hello.into_bytes();
            println!("Sending ServerHello: \n{}", bytes_to_hex(&hello_bytes, 50, ","));
            stream.write(&hello_bytes).unwrap();

            // step 3. Calculate shared secret from server private and client public
            let client_public_key = client_hello_data.get_x25519_public_key()
                .expect("could not find client x25519 key");
            println!("client public key length: {}", client_public_key.len());
            println!("key value: \n{}", bytes_to_hex(&client_public_key, 32, ","));
        }
    }
}

fn build_server_hello(client_hello_data: &ClientHelloData) -> (Record, Key) {
    let mut server_keypair = crate::crypto::x25519::KeyPair::generate();

    let legacy_version: [u8; 2] = 0x0303u16.to_be_bytes(); // TLS 1.2
    let random = crate::utils::random::random_u8_32();
    let legacy_session_id_echo = client_hello_data.session_id.clone();
    let cipher_suite = select_cipher_suite(&client_hello_data.cipher_suites)
        .expect("no compatible cipher suite found");

    let supported_versions_data = 0x0304u16.to_be_bytes().to_vec();
    let supported_versions_extension = Extension {
        extension_type: 0x002b, // supported versions value
        extension_data_length: 0x0002,
        extension_data: supported_versions_data
    };

    let key_share_extension_data = {
        let mut result = vec![];
        result.extend_from_slice(&0x001du16.to_be_bytes()); // assigned value of x25519
        result.extend_from_slice(&0x0020u16.to_be_bytes()); // 32 bytes of public key data follows
        result.extend_from_slice(&server_keypair.public.to_vec());
        println!("Server public key: \n{}", bytes_to_hex(&server_keypair.public.to_vec(), 32, ","));
        result
    };

    let key_share_extension = Extension {
        extension_type: 0x0033,
        extension_data_length: key_share_extension_data.len() as u16,
        extension_data: key_share_extension_data
    };

    let extensions = vec![supported_versions_extension, key_share_extension];
    let data = ServerHelloData {
        legacy_version,
        random,
        legacy_session_id_echo,
        cipher_suite,
        legacy_compression_method: 0x00, // always 0,
        extensions_length: extensions.len() as u16,
        extensions
    };

    let message_type = HandshakeMessageType::ServerHello(data);
    (Record::Handshake(message_type), server_keypair.private)
}

fn select_cipher_suite(client_suites: &[u16]) -> Option<[u8; 2]> {
    // 0x1301 = TLS_AES_128_GCM_SHA256
    // 0x1302 = TLS_AES_256_GCM_SHA384
    // 0x1303 = TLS_CHACHA20_POLY1305_SHA256
    let preferred = [0x1301, 0x1302, 0x1303];

    for suite in preferred {
        if client_suites.contains(&suite) {
            return Some(suite.to_be_bytes());
        }
    }
    None
}