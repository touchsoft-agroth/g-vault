use std::io::Write;
use std::net::TcpStream;
use super::response::Response;

pub struct Request<'a> {
    pub path: String,
    stream: &'a mut TcpStream
}

impl<'a> Request<'a> {
    pub fn new(path: &str, stream: &'a mut TcpStream) -> Self {
        Self {
            path: path.to_string(),
            stream
        }
    }

    pub fn respond(&mut self, response: &mut Response) {
        self.stream.write(&response.as_bytes()).unwrap();
        self.stream.flush().unwrap();
    }
}