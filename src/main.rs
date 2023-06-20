// for now i will be making an unencrypted one
// then we will be integrating stcp into this
mod types;
mod util;
mod server;
mod client;

use crate::{server::server, client::client, util::ask};

fn main() {

    let answer = ask("server or client: ");

    match answer.as_str() {
        "server" | "s" => server(),
        "client" | "c" => client(),
        &_ => println!("invalid answer: type server or client")
    }
}