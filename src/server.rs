use crate::{
    net::{decode_packet, encode_packet},
    types::{Client, ClientVec, Mode, OwnedPacket, Packet, MSG_SIZE},
    util::sleep,
};
use stcp::{bincode, AesPacket, StcpServer};
use std::{
    io::{ErrorKind, Read, Write},
    sync::{
        mpsc::{self},
        Arc, Mutex,
    },
    thread,
};
use uuid::Uuid;

pub fn server() {
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

            let aes = server.kex_with_stream(&mut socket);
            println!("KEX completed with {}", socket.peer_addr().unwrap());

            let _tx = tx.clone();
            let mut _aes = aes.clone();

            let uuid = Uuid::new_v4();

            {
                let mut clients = (*clients).lock().unwrap();
                clients.push(Client(
                    socket.try_clone().expect("failed to clone client"),
                    aes,
                    uuid,
                ));
            }

            broadcast(&mut clients, Packet::Join(uuid.to_string()), &uuid);

            thread::spawn(move || loop {
                //let mut buff = vec![0; MSG_SIZE];
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

                        if packet == Packet::Illegal {
                            // broadcast(&mut clients ,Packet::Leave(uuid.to_string()), &uuid);
                            eprintln!("severing client {addr}");
                            break;
                        }

                        println!("{:?}", packet);

                        _tx.send(OwnedPacket(packet, uuid))
                            .expect("failed to send msg");
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

        if let Ok(packet) = rx.try_recv() {
            match packet.0 {
                Packet::ClientMessage(msg) => {
                    broadcast(
                        &mut clients,
                        Packet::Message(msg, packet.1.to_string()),
                        &packet.1,
                    );
                }
                Packet::ServerCommand(command) => {
                    println!("Received {}", command);
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
        if client.2 == *ignore {
            return true;
        }

        let buf = AesPacket::encrypt_to_bytes(&mut client.1, packet.clone());

        client.0.write_all(&buf).map(|_| client).is_ok()
    });
}
