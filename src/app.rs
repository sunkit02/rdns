use anyhow::Result;

use std::{
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
    time::{Duration, Instant},
};

use crate::cli::CliArgs;
use rdns::{
    view::View, DecodeBinary, DnsPacket, DnsQtype, DnsQuery, DnsRecord, DnsRecordData, DnsType,
    EncodeBinary,
};
pub fn run_dns_resolver(args: CliArgs) -> Result<(DnsPacket, usize, Duration, bool)> {
    let socket = UdpSocket::bind("0.0.0.0:6679").unwrap();

    let query = DnsQuery::builder()
        .domain(args.domain)
        .type_(DnsQtype::A)
        .build();

    let query_start_time = Instant::now();

    let mut tcp_used = false;
    let (response, message_size) = match lookup_domain_udp(&query, &args.server_addr, &socket) {
        Ok(response) => response,
        Err(_) => {
            tcp_used = true;
            let mut stream = TcpStream::connect((args.server_addr, 53)).unwrap();
            lookup_domain_tcp(&query, &mut stream)
        }
    };

    let query_time = query_start_time.elapsed();

    Ok((response, message_size, query_time, tcp_used))
}

/// Resolves a domain name through recursively querying if needed
pub fn resolve(
    server_addr: &str,
    query: &DnsQuery,
    socket: &UdpSocket,
) -> (DnsPacket, usize, bool) {
    eprintln!("Querying '{}' for '{}'", server_addr, query.question.name);

    let mut tcp_used = false;
    let (response, message_size) = match lookup_domain_udp(&query, &server_addr, &socket) {
        Ok(response) => response,
        Err(_) => {
            tcp_used = true;
            let mut stream = TcpStream::connect((server_addr, 53)).unwrap();
            lookup_domain_tcp(&query, &mut stream)
        }
    };

    if response.is_terminal_response() {
        (response, message_size, tcp_used)
    } else if response.points_to_ns() {
        let ns_ipv4s = if response.additionals.len() >= 1 {
            response
                .additionals
                .iter()
                .filter_map(|record| match record {
                    DnsRecord {
                        type_: DnsType::A,
                        data: DnsRecordData::Ipv4Addr(ip),
                        ..
                    } => Some(ip),
                    _ => None,
                })
                .cloned()
                .collect::<Vec<String>>()
        } else {
            // no additional records attached, query for name server ip using domain
            response
                .authorities
                .iter()
                .filter_map(|record| match record {
                    DnsRecord {
                        type_: DnsType::NS,
                        data: DnsRecordData::NameServer(server),
                        ..
                    } => Some(server),
                    _ => None,
                })
                .take(1) // Only query one name server
                .map(|server_name| {
                    eprintln!(
                        "Querying '{}' for name server '{}'",
                        server_addr, server_name
                    );
                    let query = DnsQuery::builder()
                        .type_(DnsQtype::A)
                        .recursion_desired()
                        .domain(server_name.to_owned())
                        .build();
                    let (response, _, _) = resolve(server_addr, &query, socket);
                    response.answers.into_iter()
                })
                .flatten()
                .filter_map(|record| match record {
                    DnsRecord {
                        type_: DnsType::A,
                        data: DnsRecordData::Ipv4Addr(ip),
                        ..
                    } => Some(ip),
                    _ => None,
                })
                .collect::<Vec<String>>()
        };

        let ns_ip = &ns_ipv4s
            .get(0)
            .expect("Failed to find ip address for name server.");
        let (response, message_size, tcp_used) = resolve(ns_ip, query, socket);

        (response, message_size, tcp_used)
    } else {
        panic!("Something went horribliy wrong.");
    }
}

pub fn lookup_domain_tcp(query: &DnsQuery, stream: &mut TcpStream) -> (DnsPacket, usize) {
    let query = query.encode();

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

    (packet, received)
}

pub fn lookup_domain_udp(
    query: &DnsQuery,
    dns_server: &str,
    socket: &UdpSocket,
) -> Result<(DnsPacket, usize), ()> {
    let query = query.encode();

    let sent = socket.send_to(query.as_slice(), (dns_server, 53)).unwrap();
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
        Ok((packet, received))
    }
}
