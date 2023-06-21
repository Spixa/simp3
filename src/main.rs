// for now i will be making an unencrypted one
// then we will be integrating stcp into this
mod client;
mod net;
mod server;
mod types;
mod util;

use crate::{client::client, server::server, util::ask};

fn main() {

    let answer = ask("server or client: ");

    match answer.as_str() {
        "server" | "s" => server(),
        "client" | "c" => client(),
        &_ => println!("invalid answer: type server or client"),
    }
}
