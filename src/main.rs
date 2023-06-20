// for now i will be making an unencrypted one
// then we will be integrating stcp into this


use std::{io::{ErrorKind, Read, Write, self}, net::{TcpStream}, sync::mpsc::{self, TryRecvError}, thread, time::Duration, process::exit};

use aes_gcm::Aes256Gcm;
use stcp::{bincode, AesPacket, StcpServer, client_kex};

const LOCAL: &str = "127.0.0.1:37549";
const MSG_SIZE: usize = 16384;

fn sleep() {
    thread::sleep(::std::time::Duration::from_millis(50));
}

struct Client(TcpStream, Aes256Gcm);

fn server() {

    println!("generating keypairs...");
    let server = StcpServer::bind("0.0.0.0:37549").unwrap();
    println!("server running on port 37549");

    server.listener.set_nonblocking(true).expect("failed to initialize non-blocking");

    let mut clients : Vec<Client>= vec![];
    
    let (tx, rx) = mpsc::channel::<String>();

    loop {
        if let Ok((mut socket, addr)) = server.listener.accept() {
            println!("{} connected", addr);
            
            let aes = server.kex_with_stream(&mut socket);
            println!("KEX completed with {}", socket.peer_addr().unwrap());

            let _tx = tx.clone();
            let mut _aes = aes.clone();

            clients.push(Client(socket.try_clone().expect("failed to clone client"), aes));

            thread::spawn(move || loop {
                //let mut buff = vec![0; MSG_SIZE];
                let mut buff = [0 as u8; MSG_SIZE];


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
                    },

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
            clients = clients.into_iter().filter_map(|mut client| {
                let client_msg = msg.clone().into_bytes();
                let reply = AesPacket::encrypt_to_bytes(&mut client.1, client_msg.to_vec());
                
                client.0.write(&reply).map(|_| client).ok()
            }).collect::<Vec<_>>();
        }

        sleep();
    }
}

fn client() {

    let mut ip = ask("enter server IP: ");

    match &ip.as_str() {
        &"" => {
            ip.clear();
            ip.push_str(LOCAL);
        }
        &_ => {}
    }


    let mut client = TcpStream::connect(ip).expect("Stream failed to connect");


    let mut aes = client_kex(&mut client);
    let mut _aes = aes.clone();

    let (tx, rx) = mpsc::channel::<String>();

    client.set_nonblocking(true).expect("failed to initiate non-blocking");

    thread::spawn(move || loop {
        let mut buff = [0 as u8; MSG_SIZE];

        match client.read(&mut buff) {
            Ok(size) => {
                let packet = bincode::deserialize::<AesPacket>(&buff[..size]);

                match packet {
                    Ok(_) => {},
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
                    Err(_) => println!("message is not UTF-8")
                }
            },

            Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),

            Err(_) => {
                println!("connection with server was severed");
                break;
            }
        }

        match rx.try_recv() {
            Ok(msg) => {
                let buff = AesPacket::encrypt_to_bytes(&mut _aes, msg.into_bytes());
                
                client.write(&buff).expect("writing to socket failed");

                println!("message sent");
            },
            Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => break,

        }

        thread::sleep(Duration::from_micros(50));
    });

    println!("Write a Message");

    loop {
        let mut sending = String::new();
        io::stdin().read_line(&mut sending).expect("reading from stdin failed");
        let msg = sending.trim().to_string();
        if msg == ":quit" || tx.send(msg).is_err() { break; }
    }
    println!("bye bye");
}

fn ask(prompt: &str) -> String {
    print!("{}", prompt);
    std::io::stdout()
        .flush()
        .unwrap();

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .expect("failed to readline");
    answer.trim().to_lowercase().into()
}

fn main() {

    let answer = ask("server or client: ");

    match answer.as_str() {
        "server" => server(),
        "client" => client(),
        &_ => println!("invalid answer: type server or client")
    }
}