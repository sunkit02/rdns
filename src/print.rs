use chrono::prelude::*;
use chrono::{DateTime, Local};
use rdns::DnsPacket;
use std::time::Duration;

pub fn pretty_print_response(packet: &DnsPacket) {
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

pub fn print_footer(
    query_time: &Duration,
    server_ip: &str,
    server_name: &str,
    tcp_used: bool,
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
        if tcp_used { "TCP" } else { "UDP" }
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
