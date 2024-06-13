use core::panic;
use std::{mem, usize};

use rand::Rng;
use view::View;

pub mod view;

pub const TYPE_A: u16 = 1;
pub const CLASS_IN: u16 = 1;
pub const RECURSION_DESIRED: u16 = 1 << 8;

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
    pub fn new(domain_name: &str, record_type: u16) -> Self {
        let header = DnsHeader {
            id: rand::thread_rng().gen(),
            flags: RECURSION_DESIRED,
            num_questions: 1,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        };

        let question = DnsQuestion::new(domain_name, record_type, CLASS_IN);

        Self { header, question }
    }
}

impl EncodeBinary for DnsQuery {
    fn encode(&self) -> Vec<u8> {
        let header_encoded = self.header.encode().into_iter();
        let question_encoded = self.question.encode().into_iter();

        header_encoded.chain(question_encoded).collect()
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

#[derive(Debug, Clone, PartialEq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub num_questions: u16,
    pub num_answers: u16,
    pub num_authorities: u16,
    pub num_additionals: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsQuestion {
    pub name: String,
    pub type_: u16,
    pub class: u16,
}

impl DnsQuestion {
    pub fn new(dns_name: &str, type_: u16, class: u16) -> Self {
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
            self.id.to_be_bytes(),
            self.flags.to_be_bytes(),
            self.num_questions.to_be_bytes(),
            self.num_answers.to_be_bytes(),
            self.num_authorities.to_be_bytes(),
            self.num_additionals.to_be_bytes(),
        ]
        .into_iter()
        .flatten()
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
        let flags = u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap());
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
        let bytes = [self.type_.to_be_bytes(), self.class.to_be_bytes()]
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
        let type_ = u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap());
        let class = u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap());

        Self { name, type_, class }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsRecord {
    pub name: String,
    pub type_: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl DecodeBinary for DnsRecord {
    fn decode(view: &mut View) -> Self {
        let name = String::from_utf8_lossy(&decode_dns_name(view)).to_string();

        let type_ = u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap());
        let class = u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap());
        let ttl = u32::from_be_bytes(view.read_n_bytes(4).try_into().unwrap());

        let data_len = u16::from_be_bytes(view.read_n_bytes(2).try_into().unwrap()) as usize;
        let data = view.read_n_bytes_owned(data_len);

        assert_eq!(
            data_len,
            data.len(),
            "missing {} bytes of data",
            data_len - data.len()
        );

        Self {
            name,
            type_,
            class,
            ttl,
            data,
        }
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

        length = view.read_n_bytes(1)[0];
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

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;

    #[test]
    fn can_binary_encode_dns_header() {
        let (id, flags, num_questions, num_answers, num_authorities, num_additionals) =
            rand::thread_rng().gen::<(u16, u16, u16, u16, u16, u16)>();
        let header = DnsHeader {
            id,
            flags,
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
        let one_byte_short = rand::thread_rng().gen::<[u8; 11]>();

        DnsHeader::decode(&mut View::new(&one_byte_short));
    }

    #[test]
    fn can_binary_encode_dns_question() {
        let (type_, class) = rand::thread_rng().gen::<(u16, u16)>();

        let question = DnsQuestion {
            name: "www.google.com".to_owned(),
            type_,
            class,
        };

        let decoded_question = DnsQuestion::decode(&mut View::new(&question.encode()));

        assert_eq!(question, decoded_question);
    }

    #[test]
    #[should_panic]
    fn can_panic_on_decoding_invalid_dns_question() {
        let one_byte_short = rand::thread_rng().gen::<[u8; 3]>();

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
}
