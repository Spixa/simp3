use std::{
    net::TcpStream,
    sync::{Arc, Mutex},
};

use aes_gcm::Aes256Gcm;
use uuid::Uuid;

pub const LOCAL: &str = "127.0.0.1:37549";
pub const MSG_SIZE: usize = 16384;

pub struct Client(pub TcpStream, pub Aes256Gcm, pub Uuid);
pub struct OwnedPacket(pub Packet, pub Uuid);
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
    _GracefulDisconnect,
    Illegal,
}

pub enum Mode {
    Client,
    Server,
}

pub struct _Arg {
    pub name: String,
    pub argument: String,
}

pub struct _Command {
    pub name: String,
    pub args: Vec<_Arg>,
}
