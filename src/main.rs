use std::{env, net::UdpSocket};

use rdns::{view::View, DecodeBinary, DnsPacket, DnsQtype, DnsQuery, EncodeBinary};

const GOOGLE_DNS: &str = "8.8.8.8:53";
const SOME_ROOT_DNS: &str = "198.41.0.4:53";

fn main() {
    let args = env::args().collect::<Vec<String>>();

    let Some(domain_name) = args.get(1) else {
        println!("Please enter a domain name.");
        return;
    };

    let socket = UdpSocket::bind("0.0.0.0:6679").unwrap();

    let response = lookup_domain(domain_name, SOME_ROOT_DNS, &socket);

    #[cfg(debug_assertions)]
    dbg!(&response);

    println!("\n\nAnswers ({}):", response.answers.len());
    println!("{:#?}", response.answers);

    println!("\n\nAuthorities ({}):", response.authorities.len());
    println!("{:#?}", response.authorities);

    println!("\n\nAdditionals ({}):", response.additionals.len());
    println!("{:#?}", response.additionals);
}

fn lookup_domain(domain_name: &str, dns_server: &str, socket: &UdpSocket) -> DnsPacket {
    let query = DnsQuery::new(domain_name, DnsQtype::A).encode();

    let sent = socket.send_to(query.as_slice(), dns_server).unwrap();
    assert_eq!(
        sent,
        query.len(),
        "Failed to send {} bytes of the query.",
        query.len() - sent
    );

    let mut buffer = [0u8; 1024];
    let received = socket.recv(&mut buffer).unwrap();

    let mut view = View::new(&buffer[..received]);

    DnsPacket::decode(&mut view)
}
