mod server;
mod crypto;
mod http;
mod storage;
mod utils;

fn main() {
    if cfg!(debug_assertions) {
        let host = "127.0.0.1";
        let port = 443;
        let content_path = "./www";

        server::start(host, port.clone(), content_path);
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        panic!("unexpected argument length. Usage: g-vault [host] [port] [content-dir]")
    }

    let host = &args[1];
    let port = &args[2].parse::<usize>().expect("could not parse port as usize");
    let content_path = &args[3];

    server::start(host, port.clone(), content_path);
}