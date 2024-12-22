use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Instant;

pub fn start(host: &str, port: usize, static_content_path: &str) {
    let full_address = format!("{}:{}", host, port);

    let listener = std::net::TcpListener::bind(&full_address)
        .expect("Could not bind to address");

    println!("Started server on {}", &full_address);
    for incoming_stream in listener.incoming() {
        let now = Instant::now();
        let mut stream = incoming_stream.unwrap();
        handle_connection(&mut stream, static_content_path);
        println!("Request handling took: {:.2?}", now.elapsed());
    }
}

fn handle_connection(stream: &mut TcpStream, root_path: &str) {
    // write the incoming request to a buffer
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();

    // convert the request into a string and parse it
    let request_string = String::from_utf8_lossy(&buffer);
    let request_path = parse_request_path(&request_string);

    serve_requested_resource(&request_path, stream, root_path);
}

// tries to parse and extract the request path from a request.
// example:
// GET /api/user/5 HTTP/1.1 => /api/user/5
fn parse_request_path(request: &str) -> String {
    request.split_whitespace().nth(1).unwrap_or("/").to_string()
}

fn serve_requested_resource(resource_path: &str, stream: &mut TcpStream, root_path: &str) {
    // construct the full file path. account for if the path is just "/"
    let file_path = if resource_path == "/" {
        format!("{}/index.html", root_path)
    } else {
        format!("{}/{}", root_path, resource_path)
    };
    let path = Path::new(&file_path);

    let response = match std::fs::read_to_string(&path) {
        Ok(content) => {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                content.len(),
                content
            )
        },
        Err(_) => {
            "HTTP/1.1 404 NOT FOUND\r\n\r\n".to_string()
        }
    };

    stream.write(response.as_bytes()).unwrap();
    stream.flush().unwrap();
}