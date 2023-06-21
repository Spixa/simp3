fn _split_bytes<'a>(bs: &'a[u8], pred: &'a[u8]) -> Vec<&'a[u8]> {
    let mut indexes: Vec<(usize, usize)> = Vec::new();

    for (index, el) in bs.windows(pred.len()).enumerate() {
        if el == pred {
            indexes.push((index, index + pred.len()));
        }
    };

    indexes.reverse();
    
    let mut cur = bs.clone();
    let mut res: Vec<&[u8]> = Vec::new();

    for (start, end) in indexes.to_owned()  {
        let (first_left, first_right) = cur.split_at(end);
        res.push(first_right);
        
        let (second_left, _) = first_left.split_at(start);
        cur = second_left
    }

    res.push(&bs[0..1]);
    res.reverse();

    res
}

pub fn _parse_packet(buf: &[u8]) {
    let res = _split_bytes(buf, b"\x01");

    for x in res {
        dbg!(x);
    }
}

#[test]
fn test_parse() {
    let buf: &[u8] = b"\xaf\x01hello\x01spixa";
    _parse_packet(buf);
}
