use crate::{
    db_model::{establish_connection, NewUser, User},
    net::{decode_packet, encode_packet},
    types::{Auth, AuthStatus, Client, ClientVec, Mode, OwnedPacket, Packet, MSG_SIZE},
    util::sleep,
};
use colored::Colorize;
use diesel::prelude::*;
use diesel::sql_query;
use stcp::{bincode, AesPacket, StcpServer};
use std::env;
use std::{
    io::{ErrorKind, Read, Write},
    sync::{
        mpsc::{self},
        Arc, Mutex,
    },
    thread,
};
use uuid::Uuid;

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
}

pub fn do_server() {
    let _ = establish_connection();
    println!(
        "database detected ({})",
        env::var("DATABASE_URL").expect("DATABASE_URL env value not set" /* unreachable */)
    );
    println!("generating keypairs...");
    let server = StcpServer::bind("0.0.0.0:37549").unwrap();
    println!("server running on port 37549");

    server
        .listener
        .set_nonblocking(true)
        .expect("failed to initialize non-blocking");

    let mut clients: ClientVec = Arc::new(Mutex::new(vec![]));

    let (tx, rx) = mpsc::channel::<OwnedPacket>();

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

            send(
                &mut clients,
                Packet::ClientRespone(
                    String::from_utf8(include_bytes!("config/welcome.txt").to_vec()).unwrap(),
                ),
                &uuid,
            );

            thread::spawn({
                let mut clients = Arc::clone(&clients);
                move || loop {
                    let mut buff = [0_u8; MSG_SIZE];

                    match socket.read(&mut buff) {
                        Ok(size) => {
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

                            let mut uname = String::new();
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

                                eprintln!("closing connection with: {addr}");
                                break;
                            }

                            print!("{}", format!("{:?}", packet).cyan());
                            print!(" from {}", format!("{}", uuid).magenta());
                            if uname.is_empty() {
                                println!();
                            } else {
                                println!(" (AKA: {})", uname.green());
                            }

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
                        || !passwd.chars().all(|x| char::is_ascii_hexdigit(&x))
                        || passwd.len() != 128
                    {
                        send(
                            &mut clients,
                            Packet::ServerDM(
                                "Your username is NOT alphanumeric. You shall be wiped from this earth".to_string(),
                            ),
                            &packet.1 .uuid,
                        );
                        kick(&mut clients, &packet.1.uuid);
                    } else {
                        authenticate(&mut clients, &packet.1.uuid, &username);

                        let valid = match get_user_hash(username.clone()) {
                            Some(hash) => {
                                if passwd == hash {
                                    println!("{} is an old timer, actually", username);
                                    true
                                } else {
                                    send(
                                        &mut clients,
                                        Packet::ServerDM(
                                            "Incorrect password. you are kicked".to_string(),
                                        ),
                                        &packet.1.uuid,
                                    );
                                    kick(&mut clients, &packet.1.uuid);
                                    false
                                }
                            }
                            None => {
                                println!("{} is a new user!", username);
                                register_user(username.clone(), passwd.clone());
                                true
                            }
                        };
                        if valid {
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
                    if let AuthStatus::Authed(uname) = packet.1.auth_status {
                        broadcast(&mut clients, Packet::Message(msg, uname), &packet.1.uuid);
                    }
                }
                Packet::ServerCommand(command) => {
                    println!("Received {}", command);
                    let (cmd, content) = command.split_once(' ').unwrap_or((&command, ""));

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
                                Packet::ClientRespone(
                                    String::from_utf8(
                                        include_bytes!("config/version.txt").to_vec(),
                                    )
                                    .unwrap(),
                                ),
                                &packet.1.uuid,
                            );
                        }
                        "/leave" => {
                            send(
                                &mut clients,
                                Packet::ClientRespone("Goodbye, good sir.".to_string()),
                                &packet.1.uuid,
                            );
                            kick(&mut clients, &packet.1.uuid);
                        }
                        "/help" => {
                            send(
                                &mut clients,
                                Packet::ClientRespone(
                                    String::from_utf8(include_bytes!("config/help.txt").to_vec())
                                        .unwrap(),
                                ),
                                &packet.1.uuid,
                            );
                        }
                        "/list" => {
                            let response = list_clients(&mut clients);
                            send(
                                &mut clients,
                                Packet::ClientRespone(response),
                                &packet.1.uuid,
                            );
                        }
                        &_ => {
                            send(
                                &mut clients,
                                Packet::ClientRespone(
                                    "I received your command - best regards, Server".to_string(),
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

fn list_clients(clients: &mut ClientVec) -> String {
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
        .iter()
        .map(|x| x.to_string() + ",")
        .collect::<String>()
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
        broadcast(clients, Packet::Leave(uname), who);
    }

    let mut clients = (*clients).lock().unwrap();
    clients.retain(|x| x.auth.uuid != *who);
}

fn send(clients: &mut ClientVec, packet: Packet, to: &Uuid) {
    let mut clients = (*clients).lock().unwrap();
    let packet = encode_packet(packet);

    clients
        .iter_mut()
        .filter(|x| x.auth.uuid == *to)
        .for_each(|x| {
            let buf = AesPacket::encrypt_to_bytes(&mut x.aes, packet.clone());
            let _ = x.stream.write_all(&buf).map(|_| x).is_ok();
        })
}
