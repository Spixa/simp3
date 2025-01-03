use crate::ask;
use crate::{
    db_model::{establish_connection, NewUser, User},
    net::{decode_packet, encode_packet},
    types::{
        Auth, AuthStatus, Client, ClientVec, Mode, OwnedPacket, Packet, MAIN_CHANNEL, MSG_SIZE,
    },
    util::sleep,
};
use colored::Colorize;
use diesel::prelude::*;
use diesel::sql_query;
use stcp::{bincode, AesPacket, StcpServer};
use std::env;
use std::{
    collections::HashMap,
    io::{ErrorKind, Read, Write},
    sync::{
        mpsc::{self},
        Arc, Mutex,
    },
    thread,
};
use uuid::Uuid;

// TODO: move this to databse area
fn register_user(username: String, hash: String) {
    let mut connection = establish_connection();

    let new_user = NewUser {
        username: username.clone(),
        hash: hash.clone(),
    };

    diesel::insert_into(crate::schema::user::table)
        .values(&new_user)
        .execute(&mut connection)
        .expect("Error saving new user onto DB");
    println!(
        "Performed insert to database with username:{},hash:{}",
        username, hash
    );
}

// Old helper function
fn _spew_all() {
    let mut connection = establish_connection();
    let users = crate::schema::user::table
        .load::<User>(&mut connection)
        .expect("Error loading humans");
    println!("{:?}", users);
}

fn get_user_hash(username: String) -> Option<String> {
    let mut connection = establish_connection();

    let user: Result<User, _> = sql_query("SELECT * FROM user WHERE username = $1")
        .bind::<diesel::sql_types::Text, _>(username)
        .get_result(&mut connection);

    match user {
        Ok(user) => Some(user.hash),
        Err(_) => None,
    }

    // Goodbye connection
}

struct Channel {
    name: String,
    members: Vec<Uuid>,
}

impl Channel {
    fn new(name: String) -> Self {
        Self {
            name,
            members: Vec::new(),
        }
    }

    fn add_member(&mut self, member: Uuid) {
        self.members.push(member);
    }

    fn remove_member(&mut self, member: &Uuid) {
        self.members.retain(|m| m != member);
    }
}

struct ServerState {
    channels: HashMap<String, Channel>,
    client_channels: HashMap<Uuid, String>, // store client-to-channel mapping
}

pub fn do_server() {
    // Serves to check database's validity
    let _ = establish_connection();
    println!(
        "database detected ({})",
        env::var("DATABASE_URL").expect("DATABASE_URL env value not set" /* unreachable */)
    );
    let port = ask("Enter port: ");
    println!("generating keypairs...");
    let server = StcpServer::bind(format!("0.0.0.0:{}", port)).unwrap();
    println!("server running on port {}", port);

    server
        .listener
        .set_nonblocking(true)
        .expect("failed to initialize non-blocking");

    let mut clients: ClientVec = Arc::new(Mutex::new(vec![]));
    let mut server_state = Arc::new(Mutex::new(ServerState {
        channels: HashMap::new(),
        client_channels: HashMap::new(),
    }));

    let (tx, rx) = mpsc::channel::<OwnedPacket>();

    // server loop
    loop {
        if let Ok((mut socket, addr)) = server.listener.accept() {
            println!("{} connected", addr);

            let aes = match server.kex_with_stream(&mut socket) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error occured during kex with client, killing client (err: {e})");
                    break;
                }
            };
            println!("KEX completed with {}", socket.peer_addr().unwrap());

            // The original ones will be consumed by the Client vector, these are to be used within the client loops
            let _tx = tx.clone();
            let mut _aes = aes.clone();

            let uuid = Uuid::new_v4();

            {
                let mut clients = (*clients).lock().unwrap();
                clients.push(Client {
                    stream: socket.try_clone().expect("failed to clone client"),
                    aes,
                    auth: Auth {
                        uuid,
                        auth_status: AuthStatus::Unauth,
                    },
                });
            }

            // Welcome message to the newly joined client
            send(
                &mut clients,
                &Packet::ClientRespone(
                    String::from_utf8(include_bytes!("config/welcome.txt").to_vec()).unwrap(),
                ),
                &uuid,
            );

            join_or_create(&mut clients, uuid, "auth".to_string(), &mut server_state);

            // Seperate thread for the new client
            thread::spawn({
                let mut clients = Arc::clone(&clients);
                let server_state = Arc::clone(&server_state);
                move || loop {
                    let mut buff = [0_u8; MSG_SIZE];

                    match socket.read(&mut buff) {
                        Ok(size) => {
                            // Ensure packet is an encrypted AES packet
                            let packet = match bincode::deserialize::<AesPacket>(&buff[..size]) {
                                Ok(enc) => {
                                    let dec = enc.decrypt(&mut _aes);
                                    decode_packet(&dec, Mode::Server)
                                }
                                Err(err) => {
                                    if err.to_string() != "io error: unexpected end of file" {
                                        eprintln!(
                                        "Error trying to deserialize packet from {addr}, err: {err}"
                                    );
                                    }

                                    Packet::Illegal
                                }
                            };

                            // Obtain the username
                            let mut uname = String::new();
                            {
                                let mut clients = (*clients).lock().unwrap();

                                // Locate the client in the client vector for use
                                // Here auth_status is actually just the client
                                let auth_status = &clients
                                    .iter_mut()
                                    .filter(|x| x.auth.uuid == uuid)
                                    .collect::<Vec<&mut Client>>();

                                // checking whether the client exists or not
                                if auth_status.first().is_none() {
                                    break;
                                }

                                // Getting the actual auth_status
                                let auth_status = &auth_status.first().unwrap().auth.auth_status;

                                if let AuthStatus::Authed(uname_) = auth_status.clone() {
                                    uname = uname_
                                }
                            }

                            if packet == Packet::Illegal {
                                if !uname.is_empty() {
                                    broadcast(&mut clients, Packet::Leave(uname), &uuid);
                                }

                                println!(
                                    "Client sending illegal packet was kicked from the server"
                                );

                                {
                                    let mut clients = (*clients).lock().unwrap();
                                    clients.retain(|client| client.auth.uuid != uuid);

                                    let mut server_state = (*server_state).lock().unwrap();
                                    if let Some(current_channel) =
                                        server_state.client_channels.remove(&uuid)
                                    {
                                        // Remove the client from the channel as well
                                        if let Some(channel) =
                                            server_state.channels.get_mut(&current_channel)
                                        {
                                            println!(
                                                "removed {uuid} from the channel they were in"
                                            );
                                            channel.remove_member(&uuid);
                                        }
                                    }
                                }

                                break;
                            }

                            // Format console message of the new packet
                            {
                                print!("{}", format!("{:?}", packet).cyan());
                                print!(" from {}", format!("{}", uuid).magenta());
                                if uname.is_empty() {
                                    println!();
                                } else {
                                    println!(" (AKA: {})", uname.green());
                                }
                            }

                            // This block contains code for sending the packet over to the receiver channel
                            // However before that we must check whether the user is authenticated or not
                            {
                                let mut clients = (*clients).lock().unwrap();

                                let auth_status = &clients
                                    .iter_mut()
                                    .filter(|x| x.auth.uuid == uuid)
                                    .collect::<Vec<&mut Client>>();

                                if auth_status.first().is_none() {
                                    break;
                                }

                                let auth_status = &auth_status.first().unwrap().auth.auth_status;

                                if auth_status.clone() == AuthStatus::Unauth {
                                    if let Packet::Auth(_, _) = packet {
                                    } else {
                                        eprintln!("Previous client did NOT authenticate thereby being kicked from the server");
                                        break;
                                    }
                                }

                                _tx.send(OwnedPacket(
                                    packet,
                                    Auth {
                                        uuid,
                                        auth_status: auth_status.clone(),
                                    },
                                ))
                                .expect("failed to send msg");
                            }
                        }

                        // What is this even for? I forgot.
                        Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),

                        Err(_) => {
                            let mut uname = String::new();
                            {
                                let mut clients = (*clients).lock().unwrap();
                                let auth_status = &clients
                                    .iter_mut()
                                    .filter(|x| x.auth.uuid == uuid)
                                    .collect::<Vec<&mut Client>>();

                                let auth_status = &auth_status.first().unwrap().auth.auth_status;

                                if let AuthStatus::Authed(uname_) = auth_status.clone() {
                                    uname = uname_
                                }
                            }

                            if !uname.is_empty() {
                                broadcast(&mut clients, Packet::Leave(uname), &uuid);
                            }

                            {
                                let mut clients = (*clients).lock().unwrap();
                                clients.retain(|client| client.auth.uuid != uuid);

                                let mut server_state = (*server_state).lock().unwrap();
                                if let Some(current_channel) =
                                    server_state.client_channels.remove(&uuid)
                                {
                                    // Remove the client from the channel as well
                                    if let Some(channel) =
                                        server_state.channels.get_mut(&current_channel)
                                    {
                                        println!("removed {uuid} from the channel they were in");
                                        channel.remove_member(&uuid);
                                    }
                                }
                            }

                            println!("closing connection with: {}", addr);
                            break;
                        }
                    }

                    sleep();
                }
            });
        }

        if let Ok(packet) = rx.try_recv() {
            match packet.0 {
                Packet::Auth(username, passwd) => {
                    if !username.chars().all(char::is_alphanumeric)
                        || username.len() > 16
                        || username.is_empty()
                        || !passwd.chars().all(|x| char::is_ascii_hexdigit(&x)) // Password must be a hash
                        || passwd.len() != 128
                    // Further checking whether it is a hash or not
                    {
                        send(
                            &mut clients,
                            &Packet::ClientRespone(
                                String::from_utf8(
                                    include_bytes!("config/kick/generic.txt").to_vec(),
                                )
                                .unwrap(),
                            ),
                            &packet.1.uuid,
                        );
                        kick(&mut clients, &packet.1.uuid);
                    } else if list_clients(&mut clients).contains(&username) {
                        send(
                            &mut clients,
                            &Packet::ClientRespone(
                                String::from_utf8(
                                    include_bytes!("config/kick/name_exists.txt").to_vec(),
                                )
                                .unwrap(),
                            ),
                            &packet.1.uuid,
                        );
                        kick(&mut clients, &packet.1.uuid);
                    } else {
                        let valid = match get_user_hash(username.clone()) {
                            Some(hash) => {
                                if passwd == hash {
                                    println!("{} is an old timer, actually", username);
                                    true // This user already has a hash and it's matching with the one in DB
                                } else {
                                    send(
                                        &mut clients,
                                        &Packet::ServerDM(
                                            "Incorrect password. you are kicked".to_string(),
                                        ),
                                        &packet.1.uuid,
                                    );
                                    kick(&mut clients, &packet.1.uuid);
                                    false // Hash is invalid, for the user that they request
                                }
                            }
                            None => {
                                println!("{} is a new user!", username);
                                register_user(username.clone(), passwd.clone());
                                true // Hash is brand new
                            }
                        };
                        if valid {
                            join_or_create(
                                &mut clients,
                                packet.1.uuid,
                                MAIN_CHANNEL.to_string(),
                                &mut server_state,
                            );
                            authenticate(&mut clients, &packet.1.uuid, &username);
                            println!(
                                "Authenticated {} to {}",
                                packet.1.uuid.to_string().magenta(),
                                username.green()
                            );
                            broadcast(&mut clients, Packet::Join(username), &Uuid::nil());
                        }
                    }
                }
                Packet::ClientMessage(msg) => {
                    // Unauth "sends" are discarded
                    if let AuthStatus::Authed(uname) = packet.1.auth_status {
                        let server_state = server_state.lock().unwrap();
                        let uuid = packet.1.uuid;

                        let client_channel = server_state.client_channels.get(&uuid).unwrap();

                        if let Some(channel) = server_state.channels.get(client_channel) {
                            for member_uuid in &channel.members {
                                if *member_uuid != uuid {
                                    send(
                                        &mut clients,
                                        &Packet::Message(
                                            msg.clone(),
                                            uname.clone(),
                                            client_channel.to_string(),
                                        ),
                                        member_uuid,
                                    );
                                }
                            }
                        }
                        // build: no-channel mode
                        // broadcast(&mut clients, Packet::Message(msg, uname, ), &packet.1.uuid);
                    }
                }
                Packet::Ping => {}
                Packet::ClientDM(to, msg) => {
                    // Unauth DMs are discarded
                    if let AuthStatus::Authed(uname) = packet.1.auth_status {
                        match find_uuid(&mut clients, to.clone()) {
                            Some(uuid) => {
                                let msg = format!("[{} -> {}]: \"{}\"", uname, to, msg);

                                send(&mut clients, &Packet::ClientRespone(msg.clone()), &uuid);
                                send(&mut clients, &Packet::ClientRespone(msg), &packet.1.uuid);
                            }
                            None => {
                                send(
                                    &mut clients,
                                    &Packet::ClientRespone(format!(
                                        "Could not find {} for the life of me",
                                        to
                                    )),
                                    &packet.1.uuid,
                                );
                                println!("Little FYI: {uname} just tried to talk to somebody who doesnt exist! isn't that rather funny?");
                            }
                        }
                    } else {
                        // Unauthed send
                        send(
                            &mut clients,
                            &Packet::ClientRespone(
                                "You cannot send this sort of packet when unauthed".to_string(),
                            ),
                            &packet.1.uuid,
                        );
                    }
                }
                Packet::ServerCommand(command) => {
                    let (cmd, content) = command.split_once(' ').unwrap_or((&command, ""));
                    let caster = find_name(&mut clients, packet.1.uuid)
                        .unwrap_or("INVALID_USER".to_string());

                    println!("{} has cast the command: {}", caster, command);
                    match cmd {
                        "/ssc" => {
                            // super secret command
                            println!("Triggered super secret command!");
                            broadcast(
                                &mut clients,
                                Packet::Broadcast(content.to_string()),
                                &Uuid::nil(),
                            )
                        }
                        "/version" => {
                            println!("Version issued");
                            send(
                                &mut clients,
                                &Packet::ClientRespone(
                                    String::from_utf8(
                                        include_bytes!("config/version.txt").to_vec(),
                                    )
                                    .unwrap(),
                                ),
                                &packet.1.uuid,
                            );
                        }
                        "/join" => {
                            join_or_create(
                                &mut clients,
                                packet.1.uuid,
                                content.to_string(),
                                &mut server_state,
                            );
                        }
                        "/list_channels" => {
                            let response = list_channels(&mut server_state)
                                .iter()
                                .map(|x| x.to_string() + ",")
                                .collect::<String>();

                            send(
                                &mut clients,
                                &Packet::ClientRespone(response),
                                &packet.1.uuid,
                            );
                        }
                        "/leave" => {
                            send(
                                &mut clients,
                                &Packet::ClientRespone("Goodbye, good sir.".to_string()),
                                &packet.1.uuid,
                            );
                            kick(&mut clients, &packet.1.uuid);
                        }
                        "/help" => {
                            send(
                                &mut clients,
                                &Packet::ClientRespone(
                                    String::from_utf8(include_bytes!("config/help.txt").to_vec())
                                        .unwrap(),
                                ),
                                &packet.1.uuid,
                            );
                        }
                        "/ban" => {
                            send(
                                &mut clients,
                                &Packet::ClientRespone(
                                    "I am told you don't possess such power.".to_string(),
                                ),
                                &packet.1.uuid,
                            );
                        }
                        "/kick" => {
                            if caster == *content {
                                send(
                                    &mut clients,
                                    &Packet::ClientRespone(
                                        "You can't kick yourself, bozo.".to_string(),
                                    ),
                                    &packet.1.uuid,
                                );
                            } else if !content.is_empty() {
                                match find_uuid(&mut clients, content.to_string()) {
                                    Some(uuid) => {
                                        kick(&mut clients, &uuid);

                                        send(
                                            &mut clients,
                                            &Packet::ClientRespone(format!(
                                                "You successfully kicked {}",
                                                content
                                            )),
                                            &packet.1.uuid,
                                        );

                                        send(
                                            &mut clients,
                                            &Packet::ClientRespone("You were kicked".to_string()),
                                            &uuid,
                                        );

                                        println!("{} kicked {}", caster, content);
                                    }
                                    None => {
                                        send(
                                            &mut clients,
                                            &Packet::ClientRespone(format!(
                                                "Did not find \"{}\". Are they online?",
                                                content
                                            )),
                                            &packet.1.uuid,
                                        );
                                        println!(
                                            "{} tried kicking the non-existant \"{}\"",
                                            caster, content
                                        );
                                    }
                                }
                            } else {
                                send(
                                    &mut clients,
                                    &Packet::ClientRespone(
                                        "Invalid syntax. Try /kick <username>".to_string(),
                                    ),
                                    &packet.1.uuid,
                                );
                            }
                        }
                        "/list" => {
                            let response = list_clients(&mut clients)
                                .iter()
                                .map(|x| x.to_string() + ",")
                                .collect::<String>();

                            send(
                                &mut clients,
                                &Packet::ClientRespone(response),
                                &packet.1.uuid,
                            );
                        }
                        &_ => {
                            send(
                                &mut clients,
                                &Packet::ClientRespone(
                                    "Unknown command. Type /help for help".to_string(),
                                ),
                                &packet.1.uuid,
                            );
                        }
                    }
                }
                Packet::_GracefulDisconnect => {}
                _ => println!("client sent invalid packet"),
            }
        }

        sleep();
    }
}

// channel join/creation function
fn join_or_create(
    clients: &mut ClientVec,
    uuid: Uuid,
    chan_name: String,
    server_state: &mut Arc<Mutex<ServerState>>,
) {
    let mut server_state = server_state.lock().unwrap();

    if let Some(current_channel) = server_state.client_channels.remove(&uuid) {
        // Remove the client from the channel as well
        if let Some(channel) = server_state.channels.get_mut(&current_channel) {
            println!("removed {uuid} from the channel they were in");
            channel.remove_member(&uuid);

            // broadcast LeaveChannel if user has name
            if let Some(name) = find_name(clients, uuid) {
                broadcast_channel(
                    clients,
                    channel,
                    &Packet::ChannelLeave(name, channel.name.clone()),
                    Uuid::nil(),
                );
            }
        }
    }

    if let Some(channel) = server_state.channels.get_mut(&chan_name) {
        channel.add_member(uuid);

        // broadcast JoinChannel if user has name
        if let Some(name) = find_name(clients, uuid) {
            broadcast_channel(
                clients,
                channel,
                &Packet::ChannelJoin(name, chan_name.clone()),
                Uuid::nil(),
            );
        }

        println!("{uuid} joined \"{chan_name}\"");
    } else {
        // Create a new channel
        let mut new_channel = Channel::new(chan_name.clone());
        new_channel.add_member(uuid);
        server_state
            .channels
            .insert(chan_name.to_string(), new_channel);
        println!("Created new channel \"{chan_name}\"");
    }

    server_state.client_channels.insert(uuid, chan_name.clone());
}

fn broadcast(clients: &mut ClientVec, packet: Packet, ignore: &Uuid) {
    let mut clients = (*clients).lock().unwrap();
    let packet = encode_packet(packet);
    clients.retain_mut(|client| {
        if client.auth.uuid == *ignore {
            return true;
        }

        let buf = AesPacket::encrypt_to_bytes(&mut client.aes, packet.clone());
        client.stream.write_all(&buf).map(|_| client).is_ok()
    });
}

fn authenticate(clients: &mut ClientVec, who: &Uuid, to: &String) {
    let mut clients = (*clients).lock().unwrap();
    clients
        .iter_mut()
        .filter(|x| x.auth.uuid == *who)
        .for_each(|x| {
            x.auth = Auth {
                uuid: x.auth.uuid,
                auth_status: AuthStatus::Authed(to.to_string()),
            };
        });
}
fn find_uuid(clients: &mut ClientVec, alias: String) -> Option<Uuid> {
    let mut query: Vec<Uuid> = vec![];
    {
        let mut clients = (*clients).lock().unwrap();
        let registered = clients
            .iter_mut()
            .filter(|x| x.auth.auth_status != AuthStatus::Unauth)
            .collect::<Vec<&mut Client>>();

        for x in registered {
            if let AuthStatus::Authed(uname) = &x.auth.auth_status {
                if *uname == alias {
                    query.push(x.auth.uuid);
                }
            }
        }
    }

    query.first().copied()
}

fn find_name(clients: &mut ClientVec, uuid: Uuid) -> Option<String> {
    let mut clients = (*clients).lock().unwrap();
    let user = clients
        .iter_mut()
        .filter(|x| x.auth.uuid == uuid)
        .collect::<Vec<&mut Client>>();

    match user.first() {
        Some(client) => {
            if let AuthStatus::Authed(uname) = &client.auth.auth_status {
                Some(uname.clone())
            } else {
                None
            }
        }
        None => None,
    }
}

fn list_clients(clients: &mut ClientVec) -> Vec<String> {
    let mut clients = (*clients).lock().unwrap();

    let registered = clients
        .iter_mut()
        .filter(|x| x.auth.auth_status != AuthStatus::Unauth)
        .collect::<Vec<&mut Client>>();
    let mut names: Vec<String> = vec![];

    for x in registered {
        if let AuthStatus::Authed(uname) = &x.auth.auth_status {
            names.push(uname.to_string());
        }
    }

    names
}

fn list_channels(server_state: &mut Arc<Mutex<ServerState>>) -> Vec<String> {
    let server_state = server_state.lock().unwrap();
    let mut channel_names: Vec<String> = Vec::new();

    for name in server_state.channels.keys() {
        channel_names.push(name.clone());
    }

    channel_names
}

fn kick(clients: &mut ClientVec, who: &Uuid) {
    let mut uname = String::new();
    {
        let mut clients = (*clients).lock().unwrap();
        let auth_status = &clients
            .iter_mut()
            .filter(|x| x.auth.uuid == *who)
            .collect::<Vec<&mut Client>>();
        let auth_status = &auth_status.first().unwrap().auth.auth_status;
        if let AuthStatus::Authed(uname_) = auth_status.clone() {
            uname = uname_
        }
    }
    if !uname.is_empty() {
        println!("{} <client> was kicked.", uname);
        send(
            clients,
            &Packet::ClientRespone("You were kicked.".to_string()),
            who,
        );
        broadcast(clients, Packet::Leave(uname), who);
    }

    let mut clients = (*clients).lock().unwrap();
    clients.retain(|x| x.auth.uuid != *who);
}

fn broadcast_channel(clients: &mut ClientVec, channel: &Channel, packet: &Packet, ignore: Uuid) {
    for member_uuid in &channel.members {
        if *member_uuid != ignore {
            send(clients, packet, member_uuid);
        }
    }
}

fn send(clients: &mut ClientVec, packet: &Packet, to: &Uuid) {
    let mut clients = (*clients).lock().unwrap();
    let packet = encode_packet(packet.clone());

    clients
        .iter_mut()
        .filter(|x| x.auth.uuid == *to)
        .for_each(|x| {
            let buf = AesPacket::encrypt_to_bytes(&mut x.aes, packet.clone());
            let _ = x.stream.write_all(&buf).map(|_| x).is_ok();
        })
}
