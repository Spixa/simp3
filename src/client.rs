use crate::{
    types::{LOCAL, MSG_SIZE},
    util::ask,
};
use stcp::{bincode, client_kex, AesPacket};
use std::{
    io::{self, ErrorKind, Read, Write},
    net::TcpStream,
    process::exit,
    sync::mpsc::{self, TryRecvError},
    thread,
    time::Duration,
};

pub fn client() {
    let mut ip = ask("enter server IP: ");

    if ip.as_str() == "" {
        ip.push_str(LOCAL);
    }

    let mut client = TcpStream::connect(ip).expect("Stream failed to connect");

    let mut aes = client_kex(&mut client);
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
                    Err(_) => {
                        println!("server went down");
                        exit(0);
                    }
                }

                let packet = packet.unwrap();

                let decrypted_data = packet.decrypt(&mut aes);

                println!("message recv: {:?}", decrypted_data);
                match String::from_utf8(decrypted_data) {
                    Ok(str_msg) => println!("UTF-8: {}", str_msg),
                    Err(_) => println!("message is not UTF-8"),
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
                let buff = AesPacket::encrypt_to_bytes(&mut _aes, msg.into_bytes());

                client.write_all(&buff).expect("writing to socket failed");

                println!("message sent");
            }
            Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => break,
        }

        thread::sleep(Duration::from_micros(50));
    });

    println!("Write a Message");

    loop {
        let mut sending = String::new();
        io::stdin()
            .read_line(&mut sending)
            .expect("reading from stdin failed");
        let msg = sending.trim().to_string();
        if msg == ":quit" || tx.send(msg).is_err() {
            break;
        }
    }
    println!("bye bye");
}
