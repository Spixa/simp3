use randomizer::Randomizer;
use rs_sha512::{HasherContext, Sha512State};
use std::hash::{BuildHasher, Hasher};
use std::{
    io::{self, Write},
    thread,
};

pub fn sleep() {
    thread::sleep(::std::time::Duration::from_millis(50));
}

pub fn ask(prompt: &str) -> String {
    print!("{}", prompt);
    std::io::stdout().flush().unwrap();

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .expect("failed to readline");
    answer.trim().into()
}

// Useless for now lol
pub fn _derive_from_phrase(phrase: Option<String>) -> Result<String, &'static str> {
    let wordlist = include_str!("dict.txt")
        .lines()
        .collect::<Vec<&'static str>>();

    let phrase = match phrase {
        Some(v) => {
            if v.split(' ').collect::<Vec<_>>().len() != 24 {
                return Err("Input phrase isn't 24 words.");
            } else {
                v
            }
        }
        None => Randomizer::new_with_separator(24, Some(wordlist), " ")
            .string()
            .unwrap(),
    };

    println!("{}", phrase); // show phrase to user
    let mut phrase_hash = Sha512State::default().build_hasher();
    phrase_hash.write(&phrase.bytes().collect::<Vec<u8>>()[..]);
    let phrase_hash = HasherContext::finish(&mut phrase_hash);

    Ok(format!("{phrase_hash:02x}")) // store this hash, and send to server for authentication, server will store this and check against it
}
