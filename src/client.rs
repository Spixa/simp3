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

                // println!("message recv: {:?}", decrypted_data);
                // match String::from_utf8(decrypted_data) {
                //     Ok(str_msg) => println!("UTF-8: {}", str_msg),
                //     Err(_) => println!("message is not UTF-8"),
                // }

                match packet {
                    Packet::Message(content, username) => println!("{}{} {}", username.magenta(), ":".yellow(), content.green()),
                    Packet::Join(username) => println!("{} {}", username.magenta(), "joined".yellow()),
                    Packet::Leave(username) => println!("{} {}", username.magenta(), "left".yellow()),
                    Packet::ClientRespone(response) => {
                        println!("{}{} {}", "Your previous command returned".green(), ":".yellow(), response.white())
                    }
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
                    Packet::ServerCommand(msg)
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

        // io::stdin()
        //     .read_line(&mut sending)
        //     .expect("reading from stdin failed");
        let msg = sending.trim().to_string();
        if msg == ":quit" || tx.send(msg).is_err() {
            break;
        }
    }
    println!("bye bye");
}
