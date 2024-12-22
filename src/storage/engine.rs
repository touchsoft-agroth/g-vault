use std::fs;
use std::fs::File;
use std::path::Path;
use crate::storage::types::Password;

const FILE_NAME: &str = "vault";
const FILE_DIRECTORY: &str = "./data";

pub struct Client {}

impl Client {
    pub fn new() -> Self {
        ensure_file_exists();
        Self {}
    }

    pub fn read_all(&self) -> Vec<Password> {
        let mut passwords: Vec<Password> = vec![];

        for line in fs::read_to_string(build_file_path()).unwrap().lines() {
            let fields = line.split(",").collect::<Vec<&str>>();
            let id = fields[0].parse::<usize>().unwrap();
            let service_name = fields[1].to_string();
            let password_text = fields[2].to_string();

            let password = Password {
                id,
                service_name,
                password_text
            };
            passwords.push(password);
        }

        passwords
    }
}

fn build_file_path() -> std::path::PathBuf {
    Path::new(FILE_DIRECTORY).join(FILE_NAME)
}

fn ensure_file_exists() {
    if !fs::exists(FILE_DIRECTORY).unwrap() {
        fs::create_dir_all(FILE_DIRECTORY).unwrap();
    }

    let file_path = build_file_path();
    if !file_path.exists() {
        File::create(&file_path).unwrap();
    }
}