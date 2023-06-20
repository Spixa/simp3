/*
    Old code
    might come in handy later
*/

// use std::{net::{Shutdown, TcpStream}, thread, io};
// use aes_gcm::Aes256Gcm;
// use stcp::{bincode, AesPacket, StcpServer, client_kex};
// use std::io::{Write, Read};

// // struct User {
// //     stream: TcpStream,
// //     name: String,
// //     op: bool
// // }

// fn handle_client(mut stream: TcpStream, mut aes_cipher: Aes256Gcm) {
//     let mut data = [0 as u8; 4_096];

//     while match stream.read(&mut data) {
//         Ok(size) => {
//             let packet = bincode::deserialize::<AesPacket>(&data[..size]).unwrap();
//             let decrypted_data = packet.decrypt(&mut aes_cipher);

//             let mut ddstr = String::from("");
//             match std::str::from_utf8(&decrypted_data) {
//                 Ok(v) => {
//                         println!("{}: {} bytes", v, &data[0..size].len());
//                         ddstr = v.into();
//                     }
//                 Err(_) => {}
//             }

//             if ddstr == "close" {
//                 // end thread and close the stream too
//                 false
//             } else {
//                 let reply = AesPacket::encrypt_to_bytes(&mut aes_cipher, b"continue".to_vec());
//                 stream.write(&reply).unwrap();

//                 // wait for response if any
//                 true
//             }
//         }
//         Err(_) => {
//             println!(
//                 "an error occured with connection {}",
//                 stream.peer_addr().unwrap()
//             );
//             stream.shutdown(Shutdown::Both).unwrap();
//             false
//         }
//     } {}
// }

// fn ask(prompt: &str) -> String {
//     print!("{}", prompt);
//     std::io::stdout()
//         .flush()
//         .unwrap();

//     let mut answer = String::new();
//     io::stdin()
//         .read_line(&mut answer)
//         .expect("failed to readline");
//     answer.trim().to_lowercase().into()
// }

// fn main() {
//     let answer = ask("server or client: ");

//     match answer.as_str() {
//         "server" => do_server(),
//         "client" => do_client(),
//         &_ => println!("invalid answer: type server or client")
//     }
// }

// fn prompt_send(aes: &mut Aes256Gcm) -> Vec<u8> {

//     let msg: Vec<u8> = ask("send: ").into_bytes(); // ask("send: ");
//     AesPacket::encrypt_to_bytes(aes, msg)
// }

// fn do_client() {
//     let ip = ask("enter server IP: ");
//     match TcpStream::connect(&ip) {
//         Ok(mut stream) => {
//             let mut data = [0 as u8; 4_096];
//             println!("Connected to {}", ip);

//             let mut aes = client_kex(&mut stream);

//             let enc_msg = prompt_send(&mut aes);
//             stream.write(&enc_msg).unwrap();

//             while match stream.read(&mut data) {
//                 Ok(size) => {
//                     if !&data.is_empty() {

//                         let packet = bincode::deserialize::<AesPacket>(&data[..size]).unwrap();
//                         let decrypted_data = packet.decrypt(&mut aes);

//                         match std::str::from_utf8(&decrypted_data) {
//                             Ok(v) => {
//                                     println!("{}: {} bytes", v, &data[0..size].len());
//                                 }
//                             Err(_) => {}
//                         }
                        
//                         false
//                     } else {
//                         println!("Unexpected reply!");
//                         false
//                     }
//                 }
//                 Err(e) => {
//                     println!("Failed to receive data: {}", e);
//                     false
//                 }
//             } {}           
//         }
//         Err(e) => {
//             println!("Failed to connect: {e}");
//         }
//     }

// }

// fn do_server() {
//     println!("generating keypairs...");
//     let simp = StcpServer::bind("0.0.0.0:37549").unwrap();
//     println!("simp v3 is listening on port 37549");

//     // the code here runs once per client
//     for stream in simp.listener.incoming() {
//         match stream {
//             Ok(mut stream) => {
//                 println!("New connection: {}", stream.peer_addr().unwrap());
//                 let aes = simp.kex_with_stream(&mut stream);
//                 println!("KEX completed with {}", stream.peer_addr().unwrap());

//                 thread::spawn(move || {
//                 // start the handle_client loop for the client
//                     handle_client(stream, aes);
//                 });
//                 }
//             Err(e) => {
//                 println!("New connection error: {}", e);
//             }
//         }
//     }
// }

