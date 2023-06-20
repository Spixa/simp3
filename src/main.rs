// for now i will be making an unencrypted one
// then we will be integrating stcp into this


use std::{io::{ErrorKind, Read, Write, self}, net::{TcpListener, TcpStream}, sync::mpsc::{self, TryRecvError}, thread, time::Duration};

const LOCAL: &str = "127.0.0.1:37549";
const MSG_SIZE: usize = 4096;

fn sleep() {
    thread::sleep(::std::time::Duration::from_millis(50));
}

fn server() {

    let server = TcpListener::bind(LOCAL).expect("listener failed to bind");

    server.set_nonblocking(true).expect("failed to initialize non-blocking");

    let mut clients : Vec<TcpStream>= vec![];
    
    let (tx, rx) = mpsc::channel::<String>();

    loop {
        if let Ok((mut socket, addr)) = server.accept() {
            println!("{} connected", addr);

            let _tx = tx.clone();

            clients.push(socket.try_clone().expect("failed to clone client"));

            thread::spawn(move || loop {
                let mut buff = vec![0; MSG_SIZE];

                match socket.read_exact(&mut buff) {
                    Ok(_) => {
                        let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
                        let msg = String::from_utf8(msg).expect("Invalid message");
                    
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
                let mut buff = msg.clone().into_bytes();
                buff.resize(MSG_SIZE, 0);
                client.write_all(&buff).map(|_| client).ok()
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

    client.set_nonblocking(true).expect("failed to initiate non-blocking");

    let (tx, rx) = mpsc::channel::<String>();

    thread::spawn(move || loop {
        let mut buff = vec![0; MSG_SIZE];

        match client.read_exact(&mut buff) {
            Ok(_) => {
                let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
                println!("message recv: {:?}", msg);
                match String::from_utf8(msg) {
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
                let mut buff = msg.clone().into_bytes();
                buff.resize(MSG_SIZE, 0);
                client.write_all(&buff).expect("writing to socket failed");
                println!("message sent {:?}", msg);
            },
            Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => break,

        }

        thread::sleep(Duration::from_micros(50));
    });

    println!("Write a Message");

    loop {
        let mut buff = String::new();
        io::stdin().read_line(&mut buff).expect("reading from stdin failed");
        let msg = buff.trim().to_string();
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