// #![feature(proc_macro_hygiene, decl_macro)]
extern crate diesel;

mod client;
mod command;
mod db_model;
mod net;
mod schema;
mod server;
mod types;
mod util;

use crate::{db_model::establish_connection, util::ask};
use colored::Colorize;

fn main() {
    let _ = establish_connection();
    let answer = ask("server or client: ");

    match answer.to_lowercase().as_str() {
        "server" | "s" => server::do_server(),
        "client" | "c" | "" => client::do_client(),
        &_ => println!("{}", "invalid answer: type server or client".red()),
    }
}
