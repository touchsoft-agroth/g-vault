use crate::storage::engine::Client;
use crate::storage::types::Password;

pub struct Repository {
    client: Client
}

impl Repository {
    pub fn new() -> Self {
        Self {
            client: Client::new()
        }
    }

    pub fn get_all(&self) -> Vec<Password> {
        self.client.read_all()
    }
}