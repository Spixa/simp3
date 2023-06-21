use std::net::TcpStream;

use aes_gcm::Aes256Gcm;

pub const LOCAL: &str = "127.0.0.1:37549";
pub const MSG_SIZE: usize = 16384;

pub struct Client(pub TcpStream, pub Aes256Gcm);

// pub type EncryptedPacket = Vec<u8>;

// pub enum Packet {
//     Message(String, String),
//     Join(String),
//     Leave(String),
//     ServerCommand(String),
//     ClientRespone(String),
//     Ping(u32),
// }
