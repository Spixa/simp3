use crate::{
    types::{Client, MSG_SIZE},
    util::sleep,
};
use stcp::{bincode, AesPacket, StcpServer};
use std::{
    io::{ErrorKind, Read, Write},
    sync::mpsc::{self},
    thread,
};

pub fn server() {
    println!("generating keypairs...");
    let server = StcpServer::bind("0.0.0.0:37549").unwrap();
    println!("server running on port 37549");

    server
        .listener
        .set_nonblocking(true)
        .expect("failed to initialize non-blocking");

    let mut clients: Vec<Client> = vec![];

    let (tx, rx) = mpsc::channel::<String>();

    loop {
        if let Ok((mut socket, addr)) = server.listener.accept() {
            println!("{} connected", addr);

            let aes = server.kex_with_stream(&mut socket);
            println!("KEX completed with {}", socket.peer_addr().unwrap());

            let _tx = tx.clone();
            let mut _aes = aes.clone();

            clients.push(Client(
                socket.try_clone().expect("failed to clone client"),
                aes,
            ));

            thread::spawn(move || loop {
                //let mut buff = vec![0; MSG_SIZE];
                let mut buff = [0_u8; MSG_SIZE];

                match socket.read(&mut buff) {
                    Ok(size) => {
                        //let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();

                        let packet = bincode::deserialize::<AesPacket>(&buff[..size]);

                        match packet {
                            Ok(_) => {}
                            Err(_) => {
                                println!("closing connection with: {}", addr);
                                break;
                            }
                        }

                        let packet = packet.unwrap();

                        let decrypted_data = packet.decrypt(&mut _aes);

                        let msg = String::from_utf8(decrypted_data).expect("Invalid message");

                        println!("{}: {:?}", addr, msg);
                        _tx.send(msg).expect("Failed to send message");
                    }

                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),

                    Err(_) => {
                        println!("closing connection with: {}", addr);
                        break;
                    }
                }

                sleep();
            });
        }

        if let Ok(msg) = rx.try_recv() {
            clients = clients
                .into_iter()
                .filter_map(|mut client| {
                    let client_msg = msg.clone().into_bytes();
                    let reply = AesPacket::encrypt_to_bytes(&mut client.1, client_msg.to_vec());

                    client.0.write(&reply).map(|_| client).ok()
                })
                .collect::<Vec<_>>();
        }

        sleep();
    }
}
