use std::{
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
    time::{Duration, Instant},
};

use cli::CliArgs;
use error::{DnsError, NetworkError};
use rdns::{
    view::View, DecodeBinary, DnsPacket, DnsQtype, DnsQuery, DnsRecord, DnsRecordData, EncodeBinary,
};

use crate::app::error::Result;

pub mod cli;
pub mod error;
pub mod print;

pub fn run_dns_resolver(args: CliArgs) -> Result<(DnsPacket, usize, Duration, bool)> {
    let socket = UdpSocket::bind("0.0.0.0:6679").expect("failed to establish connection");

    let query = DnsQuery::builder()
        .domain(args.domain)
        .type_(DnsQtype::A)
        .build();

    let query_start_time = Instant::now();

    let mut tcp_used = false;
    let (response, message_size) = match lookup_domain_udp(&query, &args.server_addr, &socket) {
        Ok(response) => response,
        Err(DnsError::TruncatedResponse(_)) => {
            tcp_used = true;
            let mut stream = TcpStream::connect((args.server_addr, 53)).unwrap();
            lookup_domain_tcp(&query, &mut stream)?
        }
        Err(e) => return Err(e),
    };

    let query_time = query_start_time.elapsed();

    Ok((response, message_size, query_time, tcp_used))
}

/// Resolves a domain name, performs recursive querying if needed
pub fn resolve(
    server_addrs: &[String],
    query: &DnsQuery,
    socket: &UdpSocket,
    exhaustive: bool,
) -> Result<Vec<(DnsPacket, usize, bool)>> {
    let results_len = if !exhaustive { 1 } else { server_addrs.len() };
    let mut results = Vec::with_capacity(results_len);

    for server_addr in server_addrs {
        eprintln!("Querying '{}' for '{}'", server_addr, query.question.name);

        let ((response, message_size), tcp_used) =
            match lookup_domain_udp(&query, &server_addr, &socket) {
                Ok(response) => (response, false),
                Err(DnsError::TruncatedResponse(_)) => {
                    let mut stream = TcpStream::connect((server_addr.as_str(), 53)).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_millis(250)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_millis(250)))
                        .unwrap();

                    (lookup_domain_tcp(&query, &mut stream)?, true)
                }
                Err(_) => continue,
            };

        if response.is_terminal_response() {
            results.push((response, message_size, tcp_used));
        } else if response.points_to_ns() {
            let ns_ip = if response.additionals.len() >= 1 {
                response
                    .additionals
                    .into_iter()
                    .filter_map(|record| match record {
                        DnsRecord {
                            data: DnsRecordData::Ipv4Addr(ip_addr),
                            ..
                        } => Some(ip_addr),
                        _ => None,
                    })
                    .collect()
            } else {
                // Extract list of domain names of the name server pointed to
                let ns_ip_responses = response
                    .authorities
                    .into_iter()
                    .filter_map(|record| {
                        if let DnsRecordData::NameServer(ns_name) = record.data {
                            Some(ns_name)
                        } else {
                            None
                        }
                    })
                    .find_map(|ns_name| {
                        let query = DnsQuery::builder()
                            .type_(DnsQtype::A)
                            .domain(ns_name.to_owned())
                            .build();

                        resolve(&[server_addr.clone()], &query, socket, true).ok()
                    })
                    .expect("No failed to resolve name server domain.");

                let ns_ip = {
                    let (ref packet, _, _) = ns_ip_responses[0];
                    packet
                        .answers
                        .iter()
                        .filter_map(|record| match record {
                            DnsRecord {
                                data: DnsRecordData::Ipv4Addr(ip_addr),
                                ..
                            } => Some(ip_addr.to_owned()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                };

                ns_ip
            };

            let only_result = resolve(&ns_ip, query, socket, false)?
                .get(0)
                .expect(&format!(
                    "Failed to resolve ip address for domain name {}",
                    query.question.name,
                ))
                .clone();

            results.push(only_result);
        } else {
            panic!("Something went horribliy wrong.");
        }

        // Break out of loop once a single query is successful
        if !exhaustive {
            break;
        }
    }

    Ok(results)
}

pub fn lookup_domain_tcp(query: &DnsQuery, stream: &mut TcpStream) -> Result<(DnsPacket, usize)> {
    let query = query.encode();

    let query_len = (query.len() as u16).to_be_bytes();
    let mut bytes = query_len.to_vec();
    bytes.extend(query);

    stream
        .write_all(&bytes)
        .map_err(|e| DnsError::NetworkError(NetworkError::Io(e)))?;

    let mut buffer = [0u8; 1024];
    let received = stream
        .read(&mut buffer)
        .map_err(|e| DnsError::NetworkError(NetworkError::Io(e)))?;

    // Ignore first two length bytes
    let mut view = View::new(&buffer[2..received]);

    let packet = DnsPacket::decode(&mut view);

    assert!(view.is_at_end());

    Ok((packet, received))
}

pub fn lookup_domain_udp(
    query: &DnsQuery,
    dns_server: &str,
    socket: &UdpSocket,
) -> Result<(DnsPacket, usize)> {
    let query_encoded = query.encode();

    let sent = socket
        .send_to(query_encoded.as_slice(), (dns_server, 53))
        .map_err(|e| DnsError::NetworkError(NetworkError::Io(e)))?;

    assert_eq!(
        sent,
        query_encoded.len(),
        "Failed to send {} bytes of the query.",
        query_encoded.len() - sent
    );

    let mut buffer = [0u8; 1024];
    let received = socket
        .recv(&mut buffer)
        .map_err(|e| DnsError::NetworkError(NetworkError::Io(e)))?;

    let mut view = View::new(&buffer[..received]);

    let packet = DnsPacket::decode(&mut view);

    assert!(view.is_at_end());

    if packet.header.flags.is_truncated() {
        Err(error::DnsError::TruncatedResponse(query.clone()))
    } else {
        Ok((packet, received))
    }
}
