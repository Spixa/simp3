// use std::fmt::Error;

// use crate::types::{Arg, Command};

// impl Arg {
//     fn new(name: String, argument: String) -> Self {
//         Arg { name, argument }
//     }
// }

// fn parse_command(mut command: &str) -> Result<Command, Error> {
//     command = command.strip_prefix('/').ok_or(Error)?;
//     let name = parse_word(&mut command)?;
//     let args = parse_args(&mut command)?;

//     Ok(Command {
//         name: name.to_string(),
//         args,
//     })
// }
// fn parse_word<'a>(command: &'a mut &'a str) -> Result<&'a str, Error> {
//     let Some((word, rest)) = command.split_once(' ') else { return Err(Error); };
//     *command = rest.trim_start();
//     Ok(word)
// }

// fn parse_args(command: &mut &str) -> Result<Vec<Arg>, Error> {
//     let mut args = Vec::new();
//     while !command.is_empty() {
//         args.push(parse_arg(command)?);
//     }
//     Ok(args)
// }
// fn parse_arg(command: &mut &str) -> Result<Arg, Error> {
//     let name = parse_word(command)?;
//     *command = command.strip_prefix(':').ok_or(Error)?;
//     let arg = if command.starts_with('"') {
//         parse_string(command)?
//     } else {
//         parse_word(command)?
//     };
//     Ok(Arg::new(name.into(), arg.to_string()))
// }
// fn parse_string<'a>(command: &'a mut &'a str) -> Result<&'a str, Error> {
//     *command = command.strip_prefix('"').ok_or(Error)?;
//     let Some((string, rest)) = command.split_once('"') else { return Err(Error) };
//     *command = rest.trim_start();
//     Ok(string)
// }
