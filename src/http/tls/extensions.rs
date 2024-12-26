pub struct Extension {
    pub extension_type: u16,
    pub extension_data_length: u16,
    pub extension_data: Vec<u8>
}

impl Extension {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut temp = vec![];
        temp.extend_from_slice(&self.extension_type.to_be_bytes());
        temp.extend_from_slice(&self.extension_data_length.to_be_bytes());
        temp.extend_from_slice(&self.extension_data);

        temp
    }
}
