use anyhow::{anyhow, Result};
use chrono::prelude::*;

use std::{
    env,
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
    time::{Duration, Instant},
};

use rdns::{view::View, DecodeBinary, DnsPacket, DnsQtype, DnsQuery, EncodeBinary};

const APP_NAME: &str = "rdns";
const GOOGLE_DNS: (&str, Option<&str>) = ("8.8.8.8", None);
const A_ROOT_SERVER: (&str, Option<&str>) = ("198.41.0.4", Some("a.root-servers.net")); // a.root-servers.net

fn main() -> Result<()> {
    let default_server_addr = A_ROOT_SERVER.0;

    let CliArgs {
        server_addr,
        domain,
    } = parse_cli_args()?;

    let server_addr = server_addr.unwrap_or(default_server_addr.to_owned());

    let socket = UdpSocket::bind("0.0.0.0:6679").unwrap();

    let query_start_time = Instant::now();

    let mut used_tcp = false;
    let (response, message_size) = match lookup_domain(&domain, &server_addr, &socket) {
        Ok(response) => response,
        Err(_) => {
            #[cfg(debug_assertions)]
            eprintln!("->> DEBUG: Response truncated, using TCP.");

            used_tcp = true;
            let mut stream = TcpStream::connect((server_addr.clone(), 53)).unwrap();
            lookup_domain_tcp(&domain, &mut stream)
        }
    };

    let query_time = query_start_time.elapsed();
    let time = Local::now();

    pretty_print_response(&response);
    println!();

    // TODO: dynamically query the server name or server ip to be displayed in the footer
    print_footer(
        &query_time,
        &server_addr,
        &server_addr,
        used_tcp,
        &time,
        message_size,
    );
    println!();

    Ok(())
}

struct CliArgs {
    server_addr: Option<String>,
    domain: String,
}

fn parse_cli_args() -> Result<CliArgs> {
    let mut args = env::args().collect::<Vec<String>>();

    let mut server_ip = None;
    let mut domain = None;

    match args.len() {
        1 => return Err(anyhow!(get_usage_string())),
        2 => {
            if args[1].starts_with('@') {
                server_ip = Some(args[1].clone());
            } else {
                domain = Some(args[1].clone());
            }
        }
        3 => {
            if !args[1].starts_with('@') {
                return Err(anyhow!(
                    "Unknown argument: '{}'\n{}",
                    args[2],
                    get_usage_string()
                ));
            }

            // Drop the '@' in front of the server ip
            args[1].remove(0);

            server_ip = Some(args[1].clone());
            domain = Some(args[2].clone());
        }
        _ => return Err(anyhow!(get_usage_string())),
    };

    let domain = domain.ok_or(anyhow!(
        "Please enter a domain to query.\n{}",
        get_usage_string()
    ))?;

    Ok(CliArgs {
        server_addr: server_ip,
        domain,
    })
}

fn lookup_domain_tcp(domain_name: &str, stream: &mut TcpStream) -> (DnsPacket, usize) {
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

    (packet, received)
}

fn lookup_domain(
    domain_name: &str,
    dns_server: &str,
    socket: &UdpSocket,
) -> Result<(DnsPacket, usize), ()> {
    let query = DnsQuery::new(domain_name, DnsQtype::A).encode();

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

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn print_footer(
    query_time: &Duration,
    server_ip: &str,
    server_name: &str,
    used_tcp: bool,
    time: &DateTime<Local>,
    message_size: usize,
) {
    const SERVER_PORT: u16 = 53;
    println!(";; Query time: {:?}", query_time);

    println!(
        ";; SERVER: {}#{}({}) ({})",
        server_ip,
        SERVER_PORT,
        server_name,
        if used_tcp { "TCP" } else { "UDP" }
    );

    let year = time.year();
    let month = MONTHS[time.month() as usize];
    let day = time.day();
    let hour = time.hour();
    let minute = time.minute();
    let second = time.second();
    let weekday = time.weekday();

    println!(
        ";; WHEN: {} {} {} {}:{}:{} {}",
        weekday, month, day, hour, minute, second, year
    );

    println!(";; MSG SIZE  recvd: {}", message_size);
}

fn get_usage_string() -> String {
    format!("Usage: {APP_NAME} [@servername] domain")
}
