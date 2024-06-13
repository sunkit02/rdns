use std::{
    env,
    net::{Ipv4Addr, UdpSocket},
};

use rdns::{view::View, DecodeBinary, DnsPacket, DnsQtype, DnsQuery, EncodeBinary};

fn main() {
    let args = env::args().collect::<Vec<String>>();

    let Some(domain_name) = args.get(1) else {
        println!("Please enter a domain name.");
        return;
    };

    let socket = UdpSocket::bind("0.0.0.0:6679").unwrap();

    let response = lookup_domain(domain_name, "8.8.8.8:53", &socket);

    #[cfg(debug_assertions)]
    dbg!(&response);

    println!(
        "{:?}",
        Ipv4Addr::from(
            <&[u8] as TryInto<[u8; 4]>>::try_into(response.answers[0].data.as_slice()).unwrap()
        )
    )
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
