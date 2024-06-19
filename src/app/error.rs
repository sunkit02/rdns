use rdns::DnsQuery;

pub type Result<T> = std::result::Result<T, DnsError>;

#[derive(Debug)]
pub enum DnsError {
    NetworkError(NetworkError),
    TruncatedResponse(DnsQuery),
}

#[derive(Debug)]
pub enum NetworkError {
    Timeout(String),
    Io(std::io::Error),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DnsError {}
