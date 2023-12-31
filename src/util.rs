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
