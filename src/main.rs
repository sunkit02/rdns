use std::net::UdpSocket;

use rdns::{DnsQuery, EncodeBinary, CLASS_IN};

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:6679").unwrap();

    let query = DnsQuery::new("www.example.com", CLASS_IN).encode();
    println!("Query hex: {}", to_hex(&query));

    let sent = socket.send_to(query.as_slice(), "8.8.8.8:53").unwrap();
    println!("Sent {sent} bytes:\n{:?}", query);

    let mut buf = [0u8; 1024];
    let received = socket.recv(&mut buf).unwrap();

    println!("Received {received} bytes:\n{:?}", &buf[..received]);
}

fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            acc.push_str(&format!("{b:02x}"));
            acc
        })
}
