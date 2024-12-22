pub struct Response {
    status_code: Option<usize>,
    body: Option<String>
}

impl Response {
    pub fn new() -> Self {
        Self {
            status_code: None,
            body: None,
        }
    }

    pub fn with_status(&mut self, status_code: usize) {
        self.status_code = Some(status_code)
    }

    pub fn with_body(&mut self, body: &str) {
        self.body = Some(body.to_string())
    }

    pub fn as_bytes(&mut self) -> Vec<u8> {
        let mut content = vec![];

        self.build_status_line(&mut content);
        self.build_body(&mut content);

        content
    }

    fn build_body(&self, content: &mut Vec<u8>) {
        if let Some(body) = &self.body {
            let length = body.len();
            content.extend_from_slice(b"Content-Length: ");
            content.extend_from_slice(length.to_string().as_bytes());
            content.extend_from_slice(b"\r\n\r\n");
            content.extend_from_slice(body.as_bytes())
        }
    }

    fn build_status_line(&self, content: &mut Vec<u8>) {
        let status_text = match self.status_code.expect("Cannot send response with no response code") {
            200 => {
                "200 OK"
            },
            404 => {
                "404 Not found"
            },
            _ => {
                "500 Internal Server Error"
            }
        };


        content.extend_from_slice(format!("HTTP/1.1 {}\r\n", status_text).as_bytes());
    }
}