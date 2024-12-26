use std::{
    net::TcpStream,
    sync::{Arc, Mutex},
};

use aes_gcm::Aes256Gcm;
use uuid::Uuid;

pub const LOCAL: &str = "127.0.0.1:37549";
pub const MSG_SIZE: usize = 16384;

#[derive(Clone, PartialEq)]
pub enum AuthStatus {
    Unauth,
    Authed(String),
}
pub struct Auth {
    pub uuid: Uuid,
    pub auth_status: AuthStatus,
}
pub struct Client {
    pub stream: TcpStream,
    pub aes: Aes256Gcm,
    pub auth: Auth,
}
pub struct OwnedPacket(pub Packet, pub Auth);
pub type ClientVec = Arc<Mutex<Vec<Client>>>;

#[derive(Debug, PartialEq, Eq)]
pub enum Packet {
    Message(String, String),
    ClientMessage(String),
    Join(String),
    Leave(String),
    ServerCommand(String),
    ClientRespone(String),
    ServerDM(String),
    Broadcast(String),
    Auth(String, String),
    _GracefulDisconnect,
    Illegal,
}

pub enum Mode {
    Client,
    Server,
}
