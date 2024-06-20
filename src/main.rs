use std::{
    net::UdpSocket,
    time::{Duration, Instant},
};

use anyhow::Result;
use app::{
    cli::parse_cli_args,
    print::{pretty_print_response, print_footer},
};
use chrono::prelude::*;
use rdns::{DnsQtype, DnsQuery};

mod app;

const APP_NAME: &str = "rdns";
const GOOGLE_DNS: (&str, Option<&str>) = ("8.8.8.8", None);
const A_ROOT_SERVER: (&str, Option<&str>) = ("198.41.0.4", Some("a.root-servers.net")); // a.root-servers.net
const DEFAULT_SERVER_ADDR: &str = A_ROOT_SERVER.0;

fn main() -> Result<()> {
    let args = parse_cli_args()?;
    let server_addr = args.server_addr.clone();

    // let (response, message_size, query_time, tcp_used) = run_dns_resolver(args)?;

    let start_query = Instant::now();
    let socket = UdpSocket::bind("0.0.0.0:6679").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_millis(250)))
        .unwrap();

    let responses = app::resolve(
        &[server_addr.clone()],
        &DnsQuery::builder()
            .type_(DnsQtype::A)
            .domain(args.domain.clone())
            .build(),
        &socket,
        false,
    )?;

    let query_time = start_query.elapsed();

    let time = Local::now();

    let (ref response, message_size, tcp_used) = responses[0];

    pretty_print_response(response);

    // TODO: dynamically query the server name or server ip to be displayed in the footer
    print_footer(
        &query_time,
        &server_addr,
        &server_addr,
        tcp_used,
        &time,
        message_size,
    );
    println!();

    Ok(())
}
