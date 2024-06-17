use std::{fmt::Display, mem, usize};

use rand::random;
use view::View;

pub mod view;

pub trait EncodeBinary {
    fn encode(&self) -> Vec<u8>;
}

pub trait DecodeBinary {
    fn decode(bytes: &mut View) -> Self;
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsQuery {
    pub header: DnsHeader,
    pub question: DnsQuestion,
}

impl DnsQuery {
    pub fn builder() -> DnsQueryBuilder {
        DnsQueryBuilder::default()
    }
}

impl EncodeBinary for DnsQuery {
    fn encode(&self) -> Vec<u8> {
        let header_encoded = self.header.encode().into_iter();
        let question_encoded = self.question.encode().into_iter();

        header_encoded.chain(question_encoded).collect()
    }
}

#[derive(Debug, Default)]
pub struct DnsQueryBuilder {
    // Header
    id: Option<u16>,
    flags: DnsHeaderFlags,
    // Query
    domain: Option<String>,
    type_: Option<DnsQtype>,
    class: Option<DnsClass>,
}

impl DnsQueryBuilder {
    pub fn build(mut self) -> DnsQuery {
        let id = self.id.unwrap_or_else(|| random::<u16>());

        // We are building a DNS query here.
        self.flags.set_is_query();
        let flags = self.flags;

        let domain = self.domain.expect("a domain must be provided");
        let type_ = self.type_.unwrap_or(DnsQtype::A);
        let class = self.class.unwrap_or(DnsClass::IN);

        let header = DnsHeader {
            id,
            flags,
            num_questions: 1, // Only support querying of one domain for now

            // Set by server
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        };

        let question = DnsQuestion {
            name: domain,
            type_,
            class,
        };

        DnsQuery { header, question }
    }

    pub fn id(mut self, id: u16) -> Self {
        self.id = Some(id);
        self
    }

    pub fn domain(mut self, domain: String) -> Self {
        self.domain = Some(domain);
        self
    }

    pub fn type_(mut self, type_: DnsQtype) -> Self {
        self.type_ = Some(type_);
        self
    }

    pub fn class(mut self, class: DnsClass) -> Self {
        self.class = Some(class);
        self
    }

    pub fn opcode(mut self, opcode: DnsOpcode) -> Self {
        self.flags.set_opcode(opcode);
        self
    }

    pub fn authoritative_answer(mut self) -> Self {
        self.flags.set_is_authoritative_answer();
        self
    }

    pub fn truncated(mut self) -> Self {
        self.flags.set_is_truncated();
        self
    }

    pub fn recursion_desired(mut self) -> Self {
        self.flags.set_recursion_desired();
        self
    }

    pub fn recursion_available(mut self) -> Self {
        self.flags.set_recursion_available();
        self
    }

    pub fn response_code(mut self, response_code: DnsResponseCode) -> Self {
        self.flags.set_response_code(response_code);
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsPacket {
    /// Checks if the response contains a valid address. (aka ANSWER containing record(s) of type A)
    #[inline]
    pub fn is_terminal_response(&self) -> bool {
        self.answers
            .iter()
            .any(|record| matches!(record.type_, DnsType::A))
    }

    #[inline]
    pub fn points_to_ns(&self) -> bool {
        self.authorities
            .iter()
            .any(|record| matches!(record.type_, DnsType::NS))
    }
}

impl DecodeBinary for DnsPacket {
    fn decode(bytes: &mut View) -> Self {
        let header = DnsHeader::decode(bytes);

        let questions = (0..header.num_questions)
            .map(|_| DnsQuestion::decode(bytes))
            .collect();

        let answers = (0..header.num_answers)
            .map(|_| DnsRecord::decode(bytes))
            .collect();

        let authorities = (0..header.num_authorities)
            .map(|_| DnsRecord::decode(bytes))
            .collect();

        let additionals = (0..header.num_additionals)
            .map(|_| DnsRecord::decode(bytes))
            .collect();

        Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        }
    }
}

/// The header contains the following fields:
///
/// ```diagram
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
///
/// **ID**
/// A 16 bit identifier assigned by the program that generates any kind of query.  This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries.
///
/// **QR|Opcode|AA|TC|RD|RA|Z|RCODE**
/// Refer to [DnsHeaderFlags] documentation.
///
/// **QDCOUNT**         
/// an unsigned 16 bit integer specifying the number of entries in the question section.
///
/// **ANCOUNT**         
/// an unsigned 16 bit integer specifying the number of resource records in the answer section.
///
/// **NSCOUNT**
/// an unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
///
/// **ARCOUNT**
/// an unsigned 16 bit integer specifying the number of resource records in the additional records section.
///
///
#[derive(Debug, Clone, PartialEq)]
pub struct DnsHeader {
    pub id: u16,
    // TODO: Replace with a `DnsHeaderFlags` struct
    pub flags: DnsHeaderFlags,
    pub num_questions: u16,
    pub num_answers: u16,
    pub num_authorities: u16,
    pub num_additionals: u16,
}

/// The flags section of a DNS header
///
/// ```diagram
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
///
/// **QR**
/// A one bit field that specifies whether this message is a
///                 query (0), or a response (1).
///
/// **OPCODE**
/// A four bit field that specifies kind of query in this message.  This value is set by the
/// originator of a query and copied into the response.  The values are:
///
/// ```diagram
///                 0               a standard query (QUERY)
///
///                 1               an inverse query (IQUERY)
///
///                 2               a server status request (STATUS)
///
///                 3-15            reserved for future use
/// ```
///
/// **AA**
/// Authoritative Answer - this bit is valid in responses, and specifies that the responding name
/// server is an authority for the domain name in question section.
///
/// Note that the contents of the answer section may have multiple owner names because of aliases.
/// The AA bit corresponds to the name which matches the query name, or the first owner name in the
/// answer section.
///
/// **TC**
/// TrunCation - specifies that this message was truncated due to length greater than that
/// permitted on the transmission channel.
///
/// **RD**              
/// Recursion Desired - this bit may be set in a query and is copied into the response.  If RD is
/// set, it directs the name server to pursue the query recursively. Recursive query support is
/// optional.
///
/// **RA**
/// Recursion Available - this be is set or cleared in a response, and denotes whether recursive
/// query support is available in the name server.
///
/// **Z**
/// Reserved for future use.  Must be zero in all queries and responses.
///
/// **RCODE**           
/// Response code - this 4 bit field is set as part of responses.  The values have the following
/// interpretation:
///
/// ```diagram
///                 0               No error condition
///
///                 1               Format error - The name server was unable to interpret the
///                                 query.
///
///                 2               Server failure - The name server was unable to process this
///                                 query due to a problem with the name server.
///
///                 3               Name Error - Meaningful only for responses from an
///                                 authoritative name server, this code signifies that the domain
///                                 name referenced in the query does not exist.
///
///                 4               Not Implemented - The name server does not support the
///                                 requested kind of query.
///
///                 5               Refused - The name server refuses to perform the specified
///                                 operation for policy reasons.  For example, a name server may
///                                 not wish to provide the information to the particular
///                                 requester, or a name server may not wish to perform a
///                                 particular operation (e.g., zone
/// ```
///
#[derive(Debug, Copy, Clone, PartialEq, Default)]
#[repr(transparent)]
// TODO: Create a builder for this
pub struct DnsHeaderFlags(u16);

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum DnsOpcode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
    RESERVED(u8),
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum DnsResponseCode {
    /// No error condition
    NoError = 0,

    /// Format error - The name server was unable to interpret the query.
    FormatError = 1,

    /// Server failure - The name server was unable to process this query due to a problem with the
    /// name server.
    ServerFailure = 2,

    /// Name Error - Meaningful only for responses from an authoritative name server, this code
    /// signifies that the domain name referenced in the query does not exist.
    NameError = 3,

    /// Not Implemented - The name server does not support the requested kind of query.
    NotImplemented = 4,

    /// Refused - The name server refuses to perform the specified operation for policy reasons.
    /// For example, a name server may not wish to provide the information to the particular
    /// requester, or a name server may not wish to perform a particular operation (e.g., zone
    /// transfer) for particular data.
    Refused = 5,

    /// Reserved for future use.
    Reserved(u8),
}

impl DnsHeaderFlags {
    pub fn is_response(&self) -> bool {
        self.0 & 0x8000 > 0
    }

    pub fn set_is_response(&mut self) {
        self.0 |= 0x8000
    }

    pub fn is_query(&self) -> bool {
        self.0 & 0x8000 == 0
    }

    pub fn set_is_query(&mut self) {
        self.0 &= 0x7FFF
    }

    pub fn opcode(&self) -> DnsOpcode {
        let opcode = self.0 & 0x4000 >> 11;
        match opcode {
            0 => DnsOpcode::QUERY,
            1 => DnsOpcode::IQUERY,
            2 => DnsOpcode::STATUS,
            3..=15 => DnsOpcode::RESERVED(opcode as u8),
            _ => unreachable!("opcode must be in range 0..=15"),
        }
    }

    pub fn set_opcode(&mut self, opcode: DnsOpcode) {
        let opcode = match opcode {
            DnsOpcode::QUERY => 0,
            DnsOpcode::IQUERY => 1,
            DnsOpcode::STATUS => 2,
            DnsOpcode::RESERVED(code @ 3..=15) => code as u16,
            DnsOpcode::RESERVED(_) => panic!("reserved opcodes must be in range 3..=15"),
        };

        self.0 &= opcode << 11;
    }

    /// AA Authoritative Answer - this bit is valid in responses, and specifies that the responding
    /// name server is an authority for the domain name in question section.
    pub fn is_authoritative_answer(&self) -> bool {
        self.0 & 0x0400 > 0
    }

    pub fn set_is_authoritative_answer(&mut self) {
        self.0 |= 0x0400
    }

    pub fn is_truncated(&self) -> bool {
        self.0 & 0x0200 > 0
    }

    pub fn set_is_truncated(&mut self) {
        self.0 |= 0x0200
    }

    pub fn recursion_desired(&self) -> bool {
        self.0 & 0x0100 > 0
    }

    pub fn set_recursion_desired(&mut self) {
        self.0 |= 0x0100
    }

    pub fn recursion_available(&self) -> bool {
        self.0 & 0x0080 > 0
    }

    pub fn set_recursion_available(&mut self) {
        self.0 |= 0x0080
    }

    pub fn response_code(&self) -> DnsResponseCode {
        match self.0 & 0x000F {
            0 => DnsResponseCode::NoError,
            1 => DnsResponseCode::FormatError,
            2 => DnsResponseCode::ServerFailure,
            3 => DnsResponseCode::NameError,
            4 => DnsResponseCode::NotImplemented,
            5 => DnsResponseCode::Refused,
            code @ 6..=15 => DnsResponseCode::Reserved(code as u8),
            _ => unreachable!("response code should have the value in range 0..=15"),
        }
    }
    pub fn set_response_code(&mut self, response_code: DnsResponseCode) {
        let code = match response_code {
            DnsResponseCode::NoError => 0,
            DnsResponseCode::FormatError => 1,
            DnsResponseCode::ServerFailure => 2,
            DnsResponseCode::NameError => 3,
            DnsResponseCode::NotImplemented => 4,
            DnsResponseCode::Refused => 5,
            DnsResponseCode::Reserved(code @ 6..=15) => code as u16,
            DnsResponseCode::Reserved(_) => {
                panic!("reserved response code should have the value in range 6..=15")
            }
        };

        self.0 |= code;
    }

    /// Returns the abbreviated names of the flags that are set (the flag bit is one).
    pub fn get_set_flags_abbrv(&self) -> Vec<&'static str> {
        let mut flags = Vec::with_capacity(4);
        if self.is_response() {
            flags.push("qr");
        }
        if self.is_authoritative_answer() {
            flags.push("aa");
        }
        if self.is_truncated() {
            flags.push("tr");
        }
        if self.recursion_desired() {
            flags.push("rd");
        }
        if self.recursion_available() {
            flags.push("ra");
        }
        flags
    }
}

impl EncodeBinary for DnsHeaderFlags {
    fn encode(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

impl DecodeBinary for DnsHeaderFlags {
    fn decode(bytes: &mut View) -> Self {
        Self(u16::from_be_bytes(
            bytes.read_n_bytes(2).try_into().unwrap(),
        ))
    }
}

impl Display for DnsOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Display for DnsResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsQuestion {
    pub name: String,
    pub type_: DnsQtype,
    pub class: DnsClass,
}

impl DnsQuestion {
    pub fn new(dns_name: &str, type_: DnsQtype, class: DnsClass) -> Self {
        Self {
            name: dns_name.to_owned(),
            type_,
            class,
        }
    }
}

impl EncodeBinary for DnsHeader {
    fn encode(&self) -> Vec<u8> {
        [
            &self.id.to_be_bytes()[..],
            &self.flags.encode().as_slice(),
            &self.num_questions.to_be_bytes()[..],
            &self.num_answers.to_be_bytes()[..],
            &self.num_authorities.to_be_bytes()[..],
            &self.num_additionals.to_be_bytes()[..],
        ]
        .into_iter()
        .flatten()
        .copied()
        .collect::<Vec<u8>>()
    }
}
impl DecodeBinary for DnsHeader {
    fn decode(view: &mut View) -> Self {
        if view.remaining() < mem::size_of::<Self>() {
            panic!("expected exactly {} bytes", mem::size_of::<Self>());
        }

        // NOTE: The unwraps are safe because the length of `bytes` has been checked
        // by the above assert.
        let id = u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap());
        let flags = DnsHeaderFlags(u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap()));
        let num_questions = u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap());
        let num_answers = u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap());
        let num_authorities = u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap());
        let num_additionals = u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap());

        Self {
            id,
            flags,
            num_questions,
            num_answers,
            num_authorities,
            num_additionals,
        }
    }
}

impl EncodeBinary for DnsQuestion {
    fn encode(&self) -> Vec<u8> {
        let bytes = [
            (self.type_ as u16).to_be_bytes(),
            (self.class as u16).to_be_bytes(),
        ]
        .into_iter()
        .flatten();

        encode_dns_name(self.name.as_str())
            .iter()
            .copied()
            .chain(bytes)
            .collect()
    }
}

impl DecodeBinary for DnsQuestion {
    fn decode(view: &mut View) -> Self {
        let name = String::from_utf8_lossy(&decode_dns_name(view)).to_string();
        let type_ =
            DnsQtype::try_from(u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap()))
                .unwrap();
        let class =
            DnsClass::try_from(u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap()))
                .unwrap();

        Self { name, type_, class }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsRecord {
    pub name: String,
    pub type_: DnsType,
    pub class: DnsClass,
    pub ttl: u32,
    pub data: DnsRecordData,
}

impl DecodeBinary for DnsRecord {
    fn decode(view: &mut View) -> Self {
        let name = String::from_utf8_lossy(&decode_dns_name(view)).to_string();

        let type_ = DnsType::try_from(u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap()))
            .unwrap();
        let class =
            DnsClass::try_from(u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap()))
                .unwrap();
        let ttl = u32::from_be_bytes(view.read_n_bytes(4).try_into().unwrap());

        let data_len = u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap()) as usize;

        let data = match type_ {
            DnsType::A => DnsRecordData::Ipv4Addr(ipv4_to_string(view.read_n_bytes(data_len))),
            DnsType::AAAA => DnsRecordData::Ipv6Addr(ipv6_to_string(view.read_n_bytes(data_len))),
            DnsType::NS => {
                let name_bytes = decode_dns_name(view);
                let name = String::from_utf8_lossy(&name_bytes).to_string();
                DnsRecordData::NameServer(name)
            }
            DnsType::SOA => {
                let mname = String::from_utf8_lossy(&decode_dns_name(view)).to_string();
                let rname = String::from_utf8_lossy(&decode_dns_name(view)).to_string();
                let serial = u32::from_be_bytes(view.read_n_bytes(4).try_into().unwrap());
                let refresh = u32::from_be_bytes(view.read_n_bytes(4).try_into().unwrap());
                let retry = u32::from_be_bytes(view.read_n_bytes(4).try_into().unwrap());
                let expire = u32::from_be_bytes(view.read_n_bytes(4).try_into().unwrap());
                let minimum = u32::from_be_bytes(view.read_n_bytes(4).try_into().unwrap());

                DnsRecordData::StartOfAuthority {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }
            }
            DnsType::TXT => DnsRecordData::Text(decode_txt_data(view)),
            _ => DnsRecordData::Unparsed(view.read_n_bytes_owned(data_len)),
        };

        Self {
            name,
            type_,
            class,
            ttl,
            data,
        }
    }
}

/// TODO: Find and implement all data format specifications at <https://datatracker.ietf.org/doc/html/rfc1035#section-3.3>
#[derive(Debug, Clone, PartialEq)]
pub enum DnsRecordData {
    Ipv4Addr(String),
    Ipv6Addr(String),
    NameServer(String),
    StartOfAuthority {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    // TODO: Full implmentation according to <https://datatracker.ietf.org/doc/html/rfc1464>
    Text(String),
    Unparsed(Vec<u8>),
}

impl Display for DnsRecordData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsRecordData::Ipv4Addr(addr) => write!(f, "{addr}"),
            DnsRecordData::Ipv6Addr(addr) => write!(f, "{addr}"),
            DnsRecordData::NameServer(name) => write!(f, "{name}"),
            DnsRecordData::StartOfAuthority {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                write!(
                    f,
                    "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
                )
            }
            DnsRecordData::Text(text) => write!(f, "{text}"),
            DnsRecordData::Unparsed(bytes) => write!(f, "UNPARSED DATA: {bytes:?}"),
        }
    }
}

// TODO: Simplify TYPE, QTYPE, and CLASS enum representations using macros

/// TYPE fields are used in resource records.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsType {
    /// Value: 1 -> a host address
    A = 1,
    /// Value: 2 -> an authoritative name server
    NS = 2,
    /// Value: 3 -> a mail destination (Obsolete - use MX)
    MD = 3,
    /// Value: 4 -> a mail forwarder (Obsolete - use MX)
    MF = 4,
    /// Value: 5 -> the canonical name for an alias
    CNAME = 5,
    /// Value: 6 -> marks the start of a zone of authority
    SOA = 6,
    /// Value: 7 -> a mailbox domain name (EXPERIMENTAL)
    MB = 7,
    /// Value: 8 -> a mail group member (EXPERIMENTAL)
    MG = 8,
    /// Value: 9 -> a mail rename domain name (EXPERIMENTAL)
    MR = 9,
    /// Value: 10 -> a null RR (EXPERIMENTAL)
    NULL = 10,
    /// Value: 11 -> a well known service description
    WKS = 11,
    /// Value: 12 -> a domain name pointer
    PTR = 12,
    /// Value: 13 -> host information
    HINFO = 13,
    /// Value: 14 -> mailbox or mail list information
    MINFO = 14,
    /// Value: 15 -> mail exchange
    MX = 15,
    /// Value: 16 -> text strings
    TXT = 16,

    /// Value: 28 -> a host address (ipv6)
    AAAA = 28,

    // TODO: Find and implement the updated list of values for the TYPE field
    Unknown = 0,
}

// Table for fast lookup when mapping from integers to enum
const DNS_TYPES: [DnsType; 17] = [
    DnsType::A,
    DnsType::NS,
    DnsType::MD,
    DnsType::MF,
    DnsType::CNAME,
    DnsType::SOA,
    DnsType::MB,
    DnsType::MG,
    DnsType::MR,
    DnsType::NULL,
    DnsType::WKS,
    DnsType::PTR,
    DnsType::HINFO,
    DnsType::MINFO,
    DnsType::MX,
    DnsType::TXT,
    DnsType::AAAA,
];

impl TryFrom<u16> for DnsType {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        // DNS_TYPES.get(value as usize - 1).copied().ok_or(format!(
        //     "TYPE field's valid values are in the range 1..=16, got {value}"
        // ))
        if value == 28 {
            return Ok(DnsType::AAAA);
        }

        Ok(DNS_TYPES
            .get(value as usize - 1)
            .copied()
            .unwrap_or(Self::Unknown))
    }
}

impl Display for DnsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// QTYPE fields appear in the question part of a query.  QTYPES are a superset of TYPEs, hence all TYPEs are valid QTYPEs.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsQtype {
    /// Value: 1 -> a host address
    A = 1,
    /// Value: 2 -> an authoritative name server
    NS = 2,
    /// Value: 3 -> a mail destination (Obsolete - use MX)
    MD = 3,
    /// Value: 4 -> a mail forwarder (Obsolete - use MX)
    MF = 4,
    /// Value: 5 -> the canonical name for an alias
    CNAME = 5,
    /// Value: 6 -> marks the start of a zone of authority
    SOA = 6,
    /// Value: 7 -> a mailbox domain name (EXPERIMENTAL)
    MB = 7,
    /// Value: 8 -> a mail group member (EXPERIMENTAL)
    MG = 8,
    /// Value: 9 -> a mail rename domain name (EXPERIMENTAL)
    MR = 9,
    /// Value: 10 -> a null RR (EXPERIMENTAL)
    NULL = 10,
    /// Value: 11 -> a well known service description
    WKS = 11,
    /// Value: 12 -> a domain name pointer
    PTR = 12,
    /// Value: 13 -> host information
    HINFO = 13,
    /// Value: 14 -> mailbox or mail list information
    MINFO = 14,
    /// Value: 15 -> mail exchange
    MX = 15,
    /// Value: 16 -> text strings
    TXT = 16,
    /// Value: 252 -> A request for a transfer of an entire zone
    AXFR = 252,
    /// Value: 253 -> A request for mailbox-related records (MB, MG or MR)
    MAILB = 253,
    /// Value: 254 -> A request for mail agent RRs (Obsolete - see MX)
    MAILA = 254,
    /// Value: 255 -> A request for all records
    All = 255,
}

// Table for fast lookup when mapping from integers to enum
const DNS_QTYPES: [DnsQtype; 20] = [
    DnsQtype::A,
    DnsQtype::NS,
    DnsQtype::MD,
    DnsQtype::MF,
    DnsQtype::CNAME,
    DnsQtype::SOA,
    DnsQtype::MB,
    DnsQtype::MG,
    DnsQtype::MR,
    DnsQtype::NULL,
    DnsQtype::WKS,
    DnsQtype::PTR,
    DnsQtype::HINFO,
    DnsQtype::MINFO,
    DnsQtype::MX,
    DnsQtype::TXT,
    DnsQtype::AXFR,
    DnsQtype::MAILB,
    DnsQtype::MAILA,
    DnsQtype::All,
];

impl TryFrom<u16> for DnsQtype {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        const ERR_MSG: &str = "QTYPE field's valid values are in the ranges 1..=16 or 252..=255";

        let index = if matches!(value, 1..=16) {
            value - 1
        } else if matches!(value, 252..=255) {
            value - 252 + 16
        } else {
            return Err(format!("{ERR_MSG}, got: {value}"));
        };

        DNS_QTYPES
            .get(index as usize)
            .copied()
            .ok_or(format!("{ERR_MSG}, got: {value}"))
    }
}

impl Display for DnsQtype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// CLASS fields appear in resource records
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsClass {
    /// Value: 1 -> the Internet
    IN = 1,
    /// Value: 2 -> the CSNET class (Obsolete - used only for examples in some obsolete RFCs)n
    CS = 2,
    /// Value: 3 -> the CHAOS class
    CH = 3,
    /// Value: 4 -> Hesiod [Dyer 87]
    HS = 4,
}

// Table for fast lookup when mapping from integers to enum
const DNS_CLASSES: [DnsClass; 4] = [DnsClass::IN, DnsClass::CS, DnsClass::CH, DnsClass::HS];

impl TryFrom<u16> for DnsClass {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        DNS_CLASSES.get(value as usize - 1).copied().ok_or(format!(
            "CLASS field's valid values are in the range 1..=4, got {value}"
        ))
    }
}

impl Display for DnsClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

fn encode_dns_name(name: &str) -> Vec<u8> {
    name.split('.')
        .chain([""]) // for the final terminating zero
        .map(|part| {
            let bytes = part.as_bytes();
            let mut encoded = vec![bytes.len() as u8];
            encoded.extend(bytes);
            encoded
        })
        .flatten()
        .collect()
}

/// Tries to decode a one or more dns names from its binary format. This function is aware of the
/// DNS name compression scheme.
///
/// # Panics
/// This function will panic if the given [View] doesn't contain the valid bytes to decode a sequence of one or more dns names.
fn decode_dns_name(view: &mut View) -> Vec<u8> {
    if view.remaining() <= 1 {
        panic!("there must be at least one null terminating byte");
    }

    let mut parts = Vec::new();

    let mut length = view.read_n_bytes(1)[0];
    while length != 0 {
        if is_pointer(length) {
            // Zero out the first two bits and get the pointer by combining with the second octet
            let pointer = u16::from_be_bytes([(length & 0b00111111), view.read_n_bytes(1)[0]]);
            parts.extend(decode_compressed_dns_name(view, pointer as usize));
            // Insert extra period anyway to satisfy the later exclusion
            parts.push('.' as u8);
            // Break immediately since no other labels can follow a pointer
            break;
        } else {
            parts.extend(view.read_n_bytes_owned(length as usize));
            // Re-insert period between domain name parts
            parts.push('.' as u8);
        };

        length = *view
            .read_n_bytes(1)
            .get(0)
            .expect("should have enough bytes");
    }

    // Exclude the last period that was inserted redundantly
    parts.pop();

    parts
}

#[inline]
fn decode_compressed_dns_name(view: &mut View, pointer: usize) -> Vec<u8> {
    let current = view.needle();
    view.set_needle(pointer);
    let name = decode_dns_name(view);
    view.set_needle(current);
    name
}

#[inline]
fn is_pointer(double_octet: u8) -> bool {
    // Check if first two bits are set in the leading octet
    double_octet & 0b11000000 == 0b11000000
}

fn decode_txt_data(view: &mut View) -> String {
    let length = view.read_n_bytes(1)[0];
    String::from_utf8_lossy(view.read_n_bytes(length as usize)).to_string()
}

pub fn ipv4_to_string(bytes: &[u8]) -> String {
    // bytes.len() * 3 for the actual octets
    // bytes.len() * 2 - 1 for the '.' delimeters
    let mut string = String::with_capacity((bytes.len() * 3) + (bytes.len() * 2 - 1));
    let len = bytes.len();
    for (i, byte) in bytes.iter().enumerate() {
        string.push_str(byte.to_string().as_str());
        if i < len - 1 {
            string.push('.');
        }
    }

    string
}

pub fn ipv6_to_string(bytes: &[u8]) -> String {
    // Should have 128 bits
    assert_eq!(bytes.len(), 16);

    // bytes.len() * 3 for the actual octets
    // bytes.len() * 2 - 1 for the '.' delimeters
    let mut string = String::with_capacity((bytes.len() * 3) + (bytes.len() * 2 - 1));

    for i in 0..8 {
        let start = 2 * i;
        let end = start + 2;
        let segment = u16::from_be_bytes(bytes[start..end].try_into().unwrap());
        string.push_str(&format!("{segment:X}"));

        if i < 7 {
            string.push(':');
        }
    }

    string
}

#[cfg(test)]
mod tests {
    use rand::{random, thread_rng, Rng};

    use super::*;

    #[test]
    fn can_binary_encode_dns_header() {
        let (id, flags, num_questions, num_answers, num_authorities, num_additionals) =
            random::<(u16, u16, u16, u16, u16, u16)>();
        let header = DnsHeader {
            id,
            flags: DnsHeaderFlags(flags),
            num_questions,
            num_answers,
            num_authorities,
            num_additionals,
        };

        let decoded_header = DnsHeader::decode(&mut View::new(&header.encode()));

        assert_eq!(header, decoded_header);
    }

    #[test]
    #[should_panic]
    fn can_panic_on_decoding_invalid_dns_header() {
        let one_byte_short = random::<[u8; 11]>();

        DnsHeader::decode(&mut View::new(&one_byte_short));
    }

    #[test]
    fn can_binary_encode_dns_question() {
        let class = thread_rng().gen_range(1..=4);
        let type_ = thread_rng().gen_range(1..=16);

        let question = DnsQuestion {
            name: "www.google.com".to_owned(),
            type_: DnsQtype::try_from(type_).unwrap(),
            class: DnsClass::try_from(class).unwrap(),
        };

        let decoded_question = DnsQuestion::decode(&mut View::new(&question.encode()));

        assert_eq!(question, decoded_question);
    }

    #[test]
    #[should_panic]
    fn can_panic_on_decoding_invalid_dns_question() {
        let one_byte_short = random::<[u8; 3]>();

        DnsQuestion::decode(&mut View::new(&one_byte_short));
    }

    #[test]
    fn can_encode_dns_name() {
        let dns_name = "www.google.com";
        let encoded = encode_dns_name(dns_name);

        let expected = vec![
            0x3, 0x77, 0x77, 0x77, 0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d,
            0x0,
        ];

        assert_eq!(encoded, expected);
    }

    #[test]
    fn can_decode_dns_name() {
        let encoded = b"\x03www\x07example\x03com\0\x04blog\xC0\x04";
        // let encoded = b"\x03www\x07example\x03com\0";
        let mut view = View::new(encoded);

        let first = "www.example.com";
        let second = "blog.example.com";

        assert_eq!(String::from_utf8_lossy(&decode_dns_name(&mut view)), first);
        assert_eq!(String::from_utf8_lossy(&decode_dns_name(&mut view)), second);
    }

    #[test]
    fn can_decode_dns_record() {
        let orig_record = DnsRecord {
            name: "www.example.com".to_owned(),
            type_: DnsType::A,
            class: DnsClass::IN,
            ttl: 0x12345678,
            data: DnsRecordData::Ipv4Addr("93.184.215.14".to_owned()),
        };

        let mut encoded = encode_dns_name(&orig_record.name); // name
        encoded.extend((orig_record.type_ as u16).to_be_bytes()); // type_
        encoded.extend((orig_record.class as u16).to_be_bytes()); // class
        encoded.extend((orig_record.ttl as u32).to_be_bytes()); // ttl
        encoded.extend(4u16.to_be_bytes()); // data_len
        encoded.extend([93, 184, 215, 14]); // data

        let mut view = View::new(&encoded);

        let decoded = DnsRecord::decode(&mut view);
        assert_eq!(decoded, orig_record);
    }

    #[test]
    fn can_decode_dns_record_with_pointer() {
        let orig_record = DnsRecord {
            name: "blog.example.com".to_owned(),
            type_: DnsType::NS,
            class: DnsClass::IN,
            ttl: 0x12345678,
            data: DnsRecordData::NameServer("www.example.com".to_owned()),
        };

        let mut bytes = b"\x07example\x03com\0".to_vec();

        let mut encoded = encode_dns_name(&orig_record.name); // name
        encoded.extend((orig_record.type_ as u16).to_be_bytes()); // type_
        encoded.extend((orig_record.class as u16).to_be_bytes()); // class
        encoded.extend((orig_record.ttl as u32).to_be_bytes()); // ttl
        let data = b"\x03www\xC0\x00";
        encoded.extend((data.len() as u16).to_be_bytes()); // data_len
        encoded.extend(data); // data

        bytes.extend(encoded);

        let mut view = View::new(&bytes);
        // skip the inital bytes to simulate previous parsing
        view.set_needle(13);

        let decoded = DnsRecord::decode(&mut view);
        assert_eq!(decoded, orig_record);
    }

    #[test]
    fn can_decode_multiple_independent_dns_record_with_pointer() {
        let orig_record = DnsRecord {
            name: "blog.example.com".to_owned(),
            type_: DnsType::NS,
            class: DnsClass::IN,
            ttl: 0x12345678,
            data: DnsRecordData::NameServer("www.example.com".to_owned()),
        };

        let mut bytes = b"\x07example\x03com\0".to_vec();

        let mut encoded = encode_dns_name(&orig_record.name); // name
        encoded.extend((orig_record.type_ as u16).to_be_bytes()); // type_
        encoded.extend((orig_record.class as u16).to_be_bytes()); // class
        encoded.extend((orig_record.ttl as u32).to_be_bytes()); // ttl
        let data = b"\x03www\xC0\x00";
        encoded.extend((data.len() as u16).to_be_bytes()); // data_len
        encoded.extend(data); // data

        // Duplicate self twice.
        encoded.extend(encoded.clone());
        encoded.extend(encoded.clone());

        bytes.extend(encoded);

        let mut view = View::new(&bytes);
        // skip the inital bytes to simulate previous parsing
        view.set_needle(13);

        let decoded_records: Vec<DnsRecord> = (0..3)
            .map(|i| {
                let record = DnsRecord::decode(&mut view);
                dbg!(&record);
                dbg!(&view, i);
                record
            })
            .collect();

        assert_eq!(
            decoded_records,
            [orig_record.clone(), orig_record.clone(), orig_record]
        );
    }

    #[test]
    fn can_decode_dns_packet() {
        let auth = 4;
        let add = 0;
        let packet = [
            105, 146, 130, 0, 0, 1, 0, 0, 0, auth, 0, add, 6, 103, 111, 111, 103, 108, 101, 3, 99,
            111, 109, 0, 0, 1, 0, 1, 192, 19, 0, 2, 0, 1, 0, 2, 163, 0, 0, 20, 1, 108, 12, 103,
            116, 108, 100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101, 116, 0, 192, 19, 0,
            2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 106, 192, 42, 192, 19, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4,
            1, 104, 192, 42, 192, 19, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 100, 192, 42,
        ];

        let mut view = View::new(&packet);

        let packet = DnsPacket::decode(&mut view);

        assert_eq!(packet.header.num_authorities, auth as u16);
        assert_eq!(packet.header.num_additionals, add as u16);
    }
}
