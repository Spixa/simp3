mod client;
mod net;
mod server;
mod types;
mod util;

use colored::Colorize;

use crate::{util::ask};

fn main() {
    let answer = ask("server or client: ");

    match answer.to_lowercase().as_str() {
        "server" | "s" => server::do_server(),
        "client" | "c" | "" => client::do_client(),
        &_ => println!("{}", "invalid answer: type server or client".red()),
    }
}
