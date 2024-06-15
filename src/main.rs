use std::{
    env,
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
};

use rdns::{view::View, DecodeBinary, DnsPacket, DnsQtype, DnsQuery, EncodeBinary};

const GOOGLE_DNS: &str = "8.8.8.8:53";
const A_ROOT_SERVER: &str = "198.41.0.4:53"; // a.root-servers.net

fn main() {
    let args = env::args().collect::<Vec<String>>();

    let Some(domain_name) = args.get(1) else {
        println!("Please enter a domain name.");
        return;
    };

    let socket = UdpSocket::bind("0.0.0.0:6679").unwrap();

    let response = match lookup_domain(domain_name, A_ROOT_SERVER, &socket) {
        Ok(response) => response,
        Err(_) => {
            #[cfg(debug_assertions)]
            eprintln!("->> DEBUG: Response truncated, using TCP.");
            let mut stream = TcpStream::connect(A_ROOT_SERVER).unwrap();
            lookup_domain_tcp(domain_name, &mut stream)
        }
    };

    pretty_print_response(&response);
}

fn lookup_domain_tcp(domain_name: &str, stream: &mut TcpStream) -> DnsPacket {
    let query = DnsQuery::new(domain_name, DnsQtype::A).encode();
    let query_len = (query.len() as u16).to_be_bytes();
    let mut bytes = query_len.to_vec();
    bytes.extend(query);

    stream.write_all(&bytes).unwrap();

    let mut buffer = [0u8; 1024];
    let received = stream.read(&mut buffer).unwrap();

    // Ignore first two length bytes
    let mut view = View::new(&buffer[2..received]);

    let packet = DnsPacket::decode(&mut view);

    assert!(view.is_at_end());

    packet
}

fn lookup_domain(domain_name: &str, dns_server: &str, socket: &UdpSocket) -> Result<DnsPacket, ()> {
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

    let packet = DnsPacket::decode(&mut view);

    assert!(view.is_at_end());

    if packet.header.flags.is_truncated() {
        Err(())
    } else {
        Ok(packet)
    }
}

fn pretty_print_response(packet: &DnsPacket) {
    let opcode = packet.header.flags.opcode().to_string();
    let status = packet
        .header
        .flags
        .response_code()
        .to_string()
        .to_uppercase();
    let id = packet.header.id;
    let flags =
        packet
            .header
            .flags
            .get_set_flags_abbrv()
            .iter()
            .fold(String::new(), |mut acc, &f| {
                acc.push_str(f);
                acc.push(' ');
                acc
            });
    let queries = packet.header.num_questions;
    let answers = packet.header.num_answers;
    let authorities = packet.header.num_authorities;
    let additionals = packet.header.num_additionals;

    println!(";; Got answer:");
    println!(";; ->>HEADER<<- opcode: {opcode}, status: {status}, id: {id}");
    println!(";; flags: {flags}; QUERY: {queries}, ANSWER: {answers}, AUTHORITY: {authorities}, ADDITIONAL: {additionals}");

    let (name_width, ttl_width, class_width, type_width) = (24, 8, 8, 8);

    println!();
    println!(";; QUESTION SECTION ({queries}):");
    let question_name_width = name_width - 1;
    for question in &packet.questions {
        println!(
            ";{:<question_name_width$}{:<ttl_width$}{:<class_width$}{:<type_width$}",
            question.name,
            "",
            question.class.to_string(),
            question.type_.to_string()
        );
    }

    if answers > 0 {
        println!();
        println!(";; ANSWER SECTION ({answers}):");
        for answer in &packet.answers {
            println!(
                "{:<name_width$}{:<ttl_width$}{:<class_width$}{:<type_width$}{}",
                answer.name,
                answer.ttl,
                answer.class.to_string(),
                answer.type_.to_string(),
                answer.data
            );
        }
    }

    if authorities > 0 {
        println!();
        println!(";; AUTHORITY SECTION ({authorities}):");
        for authority in &packet.authorities {
            println!(
                "{:<name_width$}{:<ttl_width$}{:<class_width$}{:<type_width$}{}",
                authority.name,
                authority.ttl,
                authority.class.to_string(),
                authority.type_.to_string(),
                authority.data
            );
        }
    }

    if additionals > 0 {
        println!();
        println!(";; ADDITIONAL SECTION ({additionals}):");
        for additional in &packet.additionals {
            println!(
                "{:<name_width$}{:<ttl_width$}{:<class_width$}{:<type_width$}{}",
                additional.name,
                additional.ttl,
                additional.class.to_string(),
                additional.type_.to_string(),
                additional.data,
            );
        }
    }
}
