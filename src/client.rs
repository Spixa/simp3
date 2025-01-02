use crate::{
    net::{decode_packet, encode_packet},
    types::{Mode, Packet, LOCAL, MSG_SIZE},
    util::ask,
};
use colored::Colorize;
use stcp::{bincode, client_kex, AesPacket};
use std::{
    io::{ErrorKind, Read, Write},
    net::TcpStream,
    process::exit,
    sync::mpsc::{self, TryRecvError},
    thread,
    time::Duration,
};

use rs_sha512::HasherContext;
use rs_sha512::Sha512State;
use std::hash::BuildHasher;
use std::hash::Hasher;

pub fn do_client() {
    let mut ip = ask("enter server IP: ");

    if ip.as_str() == "" {
        ip.push_str(LOCAL);
    }

    let mut client = TcpStream::connect(ip).expect("Stream failed to connect");

    let mut aes = match client_kex(&mut client) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error occured during kex, dying (err: {e})");
            std::process::exit(-1);
        }
    };
    let mut _aes = aes.clone();

    let (tx, rx) = mpsc::channel::<String>();

    client
        .set_nonblocking(true)
        .expect("failed to initiate non-blocking");

    {
        let uname = ask("Enter username: ");

        let passwd = ask("Enter password: ");
        let mut phrase_hash = Sha512State::default().build_hasher();
        phrase_hash.write(&passwd.bytes().collect::<Vec<u8>>()[..]);
        let phrase_hash = HasherContext::finish(&mut phrase_hash);

        let buf = encode_packet(Packet::Auth(uname, format!("{phrase_hash:02x}")));
        let enc = AesPacket::encrypt_to_bytes(&mut _aes, buf);
        client.write_all(&enc).expect("writing to socket failed");
    }

    thread::spawn(move || loop {
        let mut buff = [0_u8; MSG_SIZE];

        match client.read(&mut buff) {
            Ok(size) => {
                let packet = bincode::deserialize::<AesPacket>(&buff[..size]);

                match packet {
                    Ok(_) => {}
                    Err(e) => {
                        println!("server went down");
                        println!("error: {e}");
                        exit(0);
                    }
                }

                let packet = packet.unwrap();

                let decrypted_data = packet.decrypt(&mut aes);

                let packet = decode_packet(&decrypted_data, Mode::Client);

                match packet {
                    Packet::Message(content, username, channel) => {
                        println!(
                            "{}{}{}{} {}{} {}",
                            "[".bright_black(),
                            "#".blue(),
                            channel.bright_blue(),
                            "]".bright_black(),
                            username.magenta(),
                            ":".yellow(),
                            content.green()
                        )
                    }
                    Packet::Join(username) => {
                        println!("{} {}", username.magenta(), "joined".yellow())
                    }
                    Packet::Leave(username) => {
                        println!("{} {}", username.magenta(), "left".yellow())
                    }
                    Packet::ClientRespone(response) => {
                        println!(
                            "{}{} {}",
                            "Server >>".green(),
                            ":".yellow(),
                            response.white()
                        )
                    }
                    Packet::ServerDM(msg) => format_broadcast(String::from("server"), msg),
                    Packet::Broadcast(msg) => format_broadcast(String::from("simp3"), msg),
                    _ => panic!("{}", "Recv Illegal packet".red()),
                }
            }

            Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),

            Err(_) => {
                println!("connection with server was severed");
                break;
            }
        }

        match rx.try_recv() {
            Ok(msg) => {
                let packet = if msg.starts_with('/') {
                    handle_slash(msg)
                } else {
                    Packet::ClientMessage(msg)
                };

                let buf = encode_packet(packet);
                let enc = AesPacket::encrypt_to_bytes(&mut _aes, buf);

                client.write_all(&enc).expect("writing to socket failed");
            }
            Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => break,
        }

        thread::sleep(Duration::from_micros(50));
    });

    println!("Write a Message");

    loop {
        let sending = ask("");
        let msg = sending.trim().to_string();
        if msg == ":quit" || tx.send(msg).is_err() {
            break;
        }
    }
    println!("bye bye");
}

fn format_broadcast(by: String, msg: String) {
    print!(
        "{}{}{} ",
        "[".bright_black(),
        by.green(),
        "]".bright_black()
    );

    let words = msg.split_whitespace();
    #[derive(PartialEq)]
    enum Color {
        Red,
        Default,
    }
    let mut red = Color::Default;

    for x in words {
        if x.starts_with('"') {
            red = Color::Red;
        }

        if red == Color::Red {
            print!("{} ", x.red());
        } else if x.parse::<i64>().is_ok() {
            print!("{} ", x.bright_magenta());
        } else if x.starts_with('#') {
            print!("{} ", x.bright_blue());
        } else if !x.split_once('.').unwrap_or((x, "")).1.is_empty() {
            print!("{} ", x.bright_green());
        } else if x.to_lowercase() == "spixa" {
            print!("{} ", "Spixa".bright_cyan());
        } else if x.starts_with('/') {
            print!("{} ", x.bold().blue())
        } else {
            print!("{} ", x.yellow());
        }

        if x.ends_with('"') {
            red = Color::Default;
        }
    }
    println!();
}

fn handle_slash(msg: String) -> Packet {
    if msg.starts_with("/dm") {
        if msg.len() >= 4 {
            let dm_cmd = msg[4..].to_string();
            let (user, cont) = dm_cmd.split_once(' ').unwrap_or(("%nobody%", "%nothing%"));
            Packet::ClientDM(user.to_string(), cont.to_string())
        } else {
            println!("[client] internal command for DM is: /dm <uname> <content>");
            Packet::Ping
        }
    } else {
        // Everything else will be a "server-side" command
        Packet::ServerCommand(msg)
    }
}
