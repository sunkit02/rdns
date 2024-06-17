use std::env;

use anyhow::{anyhow, Result};

use crate::APP_NAME;
use crate::DEFAULT_SERVER_ADDR;

pub struct CliArgs {
    pub server_addr: String,
    pub domain: String,
}

pub fn parse_cli_args() -> Result<CliArgs> {
    let mut args = env::args().collect::<Vec<String>>();

    let mut server_addr = None;
    let mut domain = None;

    match args.len() {
        1 => return Err(anyhow!(get_usage_string())),
        2 => {
            if args[1].starts_with('@') {
                server_addr = Some(args[1].clone());
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

            server_addr = Some(args[1].clone());
            domain = Some(args[2].clone());
        }
        _ => return Err(anyhow!(get_usage_string())),
    };

    let domain = domain.ok_or(anyhow!(
        "Please enter a domain to query.\n{}",
        get_usage_string()
    ))?;
    let server_addr = server_addr.unwrap_or(DEFAULT_SERVER_ADDR.to_owned());

    Ok(CliArgs {
        server_addr,
        domain,
    })
}

fn get_usage_string() -> String {
    format!("Usage: {APP_NAME} [@servername] domain")
}
