pub fn bytes_to_hex(bytes: &[u8], bytes_per_line: usize, separator: &str) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let mut hex_output = String::with_capacity(bytes.len() * 3);

    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 && i % bytes_per_line == 0 {
            hex_output.push('\n');
        };

        if i % bytes_per_line != 0 {
            hex_output.push_str(separator);
        }

        hex_output.push_str(&format!("{:02x}", byte));
    };

    hex_output
}