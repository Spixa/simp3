use crate::types::{Mode, Packet};

fn _split_bytes<'a>(bs: &'a [u8], pred: &'a [u8]) -> Vec<&'a [u8]> {
    let mut indexes: Vec<(usize, usize)> = Vec::new();

    for (index, el) in bs.windows(pred.len()).enumerate() {
        if el == pred {
            indexes.push((index, index + pred.len()));
        }
    }

    indexes.reverse();

    let mut cur = bs.clone();
    let mut res: Vec<&[u8]> = Vec::new();

    for (start, end) in indexes.to_owned() {
        let (first_left, first_right) = cur.split_at(end);
        res.push(first_right);

        let (second_left, _) = first_left.split_at(start);
        cur = second_left
    }

    res.push(&bs[0..1]);
    res.reverse();

    res
}

pub fn decode_packet(buf: &[u8], mode: Mode) -> Packet {
    let mut strvec: Vec<String> = vec![];
    for x in _split_bytes(buf, b"\x01") {
        strvec.push(String::from_utf8(x.to_vec()).unwrap());
    }

    let res = match strvec[0].as_str() {
        "0" => match mode {
            Mode::Client => Packet::Message(strvec[1].clone(), strvec[2].clone()),
            Mode::Server => Packet::ClientMessage(strvec[1].clone()),
        },
        "1" => Packet::Join(strvec[1].clone()),
        "2" => Packet::Leave(strvec[1].clone()),
        "5" => Packet::ServerCommand(strvec[1].clone()),
        "6" => Packet::ClientRespone(strvec[1].clone()),
        _else => Packet::Illegal,
    };

    res
}

/*
    SIMP 3 specification:

    Message packets are prefixed with ASCII b"0" or \x30
    Join is b"1" or \x31
    Leave is b"2" or \x32
    And the packets expand so forth until \xFF
*/

pub fn encode_packet(packet: Packet) -> Vec<u8> {
    let result = match packet {
        Packet::Message(content, username) => {
            format!("0\x01{}\x01{}", content, username).into_bytes()
        }
        Packet::ClientMessage(content) => format!("0\x01{}", content).into_bytes(),
        Packet::Join(username) => format!("1\x01{}", username).into_bytes(),
        Packet::Leave(username) => format!("2\x01{}", username).into_bytes(),
        Packet::ServerCommand(command) => format!("5\x01{}", command).into_bytes(),
        Packet::ClientRespone(response) => format!("6\x01{}", response).into_bytes(),
        Packet::Illegal => panic!("You cannot send an illegal packet!"),
    };

    result
}
