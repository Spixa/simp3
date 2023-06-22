use std::net::TcpStream;

use aes_gcm::Aes256Gcm;

pub const LOCAL: &str = "127.0.0.1:37549";
pub const MSG_SIZE: usize = 16384;

pub struct Client(pub TcpStream, pub Aes256Gcm);

#[derive(Debug)]
pub enum Packet {
    Message(String, String),
    ClientMessage(String),
    Join(String),
    Leave(String),
    ServerCommand(String),
    ClientRespone(String),
    Illegal,
}

// pub struct OwnedPacket<'a>(pub Packet, pub &'a Client);

pub enum Mode {
    Client,
    Server,
}
