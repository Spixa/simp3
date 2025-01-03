use std::{
    collections::HashMap,
    net::TcpStream,
    sync::{Arc, Mutex},
};

use aes_gcm::Aes256Gcm;
use uuid::Uuid;

pub const LOCAL: &str = "127.0.0.1:37549";
pub const MAIN_CHANNEL: &str = "main";
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

pub struct Channel {
    pub name: String,
    pub locked: bool,
    pub members: Vec<Uuid>,
}

impl Channel {
    pub fn new(name: String, locked: bool) -> Self {
        Self {
            name,
            locked,
            members: Vec::new(),
        }
    }

    pub fn add_member(&mut self, member: Uuid) {
        self.members.push(member);
    }

    pub fn remove_member(&mut self, member: &Uuid) {
        self.members.retain(|m| m != member);
    }
}

pub struct ServerState {
    pub channels: HashMap<String, Channel>,
    pub client_channels: HashMap<Uuid, String>, // store client-to-channel mapping
}

pub struct OwnedPacket(pub Packet, pub Auth);
pub type ClientVec = Arc<Mutex<Vec<Client>>>;
pub type ServerStateGuard = Arc<Mutex<ServerState>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Message(String, String, String),
    ClientMessage(String),
    ClientDM(String, String),
    Join(String),
    Leave(String),
    ServerCommand(String),
    ClientRespone(String),
    ServerDM(String),
    Broadcast(String),
    Auth(String, String),
    Ping,
    ChannelJoin(String, String),
    ChannelLeave(String, String),
    _GracefulDisconnect,
    Illegal,
}

pub enum Mode {
    Client,
    Server,
}
