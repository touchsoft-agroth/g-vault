use super::extensions::Extension;

pub enum HandshakeMessageType {
    ClientHello(ClientHelloData),
    ServerHello(ServerHelloData)
}

impl HandshakeMessageType {
    pub fn into_bytes(&self) -> Vec<u8> {
        let mut result = vec![];

        match self {
            Self::ServerHello(server_hello) => {
                result.extend_from_slice(&server_hello.to_bytes());
            },
            _ => panic!("unsupported handshake message type")
        }

        result
    }
}

impl HandshakeMessageType {
    pub fn parse(buffer: &[u8]) -> Result<HandshakeMessageType, &'static str> {
        let header = HandshakeHeader::parse(buffer)?;
        if buffer.len() < HandshakeHeader::EXPECTED_LENGTH + header.length {
            return Err("Buffer is shorter than declared handshake message length");
        }

        match header.handshake_type {
            1 => {
                let data = ClientHelloData::parse(&buffer[HandshakeHeader::EXPECTED_LENGTH..])?;
                Ok(HandshakeMessageType::ClientHello(data))
            },
            _ => Err("Unexpected handshake type")
        }
    }
}

struct HandshakeHeader {
    pub handshake_type: u8,
    pub length: usize,
}

impl HandshakeHeader {
    pub const EXPECTED_LENGTH: usize = 4;

    pub fn parse(buffer: &[u8]) -> Result<HandshakeHeader, &'static str> {
        if buffer.len() < Self::EXPECTED_LENGTH {
            return Err("Handshake header is shorter than expected length");
        }

        let handshake_type = buffer[0];
        let length = {
            let b1 = buffer[1] as u32;
            let b2 = buffer[2] as u32;
            let b3 = buffer[3] as u32;

            (b1 << 16) | (b2 << 8) | b3
        } as usize;

        Ok(HandshakeHeader {
            handshake_type,
            length
        })
    }
}

pub struct ClientHelloData {
    pub protocol_version: u16,
    pub random: [u8; 32], // 4 bytes timestamp + 28 bytes random
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>
}

impl ClientHelloData {
    pub fn parse(buffer: &[u8]) -> Result<ClientHelloData, &'static str> {
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

        let mut extensions: Vec<Extension> = Vec::with_capacity(extensions_length);
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

            let extension = Extension {
                extension_type,
                extension_data_length: extension_length,
                extension_data
            };

            extensions.push(extension);
        }

        Ok(ClientHelloData{
            protocol_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions
        })
    }

    const EXTENSION_KEY_SHARE: u16 = 0x0033;

    fn get_client_key_share(&self) -> Option<&Extension> {
        for extension in &self.extensions {
            if extension.extension_type == Self::EXTENSION_KEY_SHARE {
                let data = &extension.extension_data;
                if data.len() < 4 {
                    return None;
                }

                let key_exchange_length = extension.extension_data_length;
                if data.len() < key_exchange_length as usize {
                    return None;
                }

                return Some(extension);
            }
        };

        None
    }

    const X25519_GROUP: u16 = 0x001d;

    pub fn get_x25519_public_key(&self) -> Option<[u8; 32]> {
        let key = self.get_client_key_share()?;
        let key_share_data = &key.extension_data;

        // Walk through all the key shares
        let mut pos = 0;
        while pos + 4 <= key_share_data.len() {
            let group = ((key_share_data[pos] as u16) << 8) | key_share_data[pos + 1] as u16;
            let length = ((key_share_data[pos + 2] as u16) << 8) | key_share_data[pos + 3] as u16;

            if group == Self::X25519_GROUP {
                if pos + 4 + length as usize > key_share_data.len() || length != 32 {
                    return None;
                }

                let mut public_key = [0u8; 32];
                public_key.copy_from_slice(&key_share_data[pos + 4..pos + 4 + 32]);
                return Some(public_key);
            }

            pos += 4 + length as usize;
        }

        None
    }
}

pub struct ServerHelloData {
    pub legacy_version: [u8; 2],
    pub random: [u8; 32],
    pub legacy_session_id_echo: Vec<u8>,
    pub cipher_suite: [u8; 2],
    pub legacy_compression_method: u8,
    pub extensions_length: u16,
    pub extensions: Vec<Extension>
}

impl ServerHelloData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = vec![];

        result.extend_from_slice(&self.legacy_version);
        result.extend_from_slice(&self.random);
        result.extend_from_slice(&self.legacy_session_id_echo);
        result.extend_from_slice(&self.cipher_suite);
        result.push(self.legacy_compression_method);
        result.extend_from_slice(&self.extensions_length.to_be_bytes());
        for extension in self.extensions.iter() {
            result.extend_from_slice(&extension.to_bytes());
        };

        result
    }
}


