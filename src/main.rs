use std::{env, net::UdpSocket};

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

    let response = lookup_domain(domain_name, A_ROOT_SERVER, &socket);

    pretty_print_response(&response);
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

fn pretty_print_response(packet: &DnsPacket) {
    let opcode = "unimplemented";
    let status = "unimplemented";
    let id = packet.header.id;
    let flags = "unimplemented";
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
