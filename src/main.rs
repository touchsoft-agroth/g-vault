mod server;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 4 {
        panic!("unexpected argument length")
    }

    let host = &args[1];
    let port = &args[2].parse::<usize>().expect("could not parse port as usize");
    let content_path = &args[3];

    server::start(host, port.clone(), content_path);
}