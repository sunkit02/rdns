use rand::Rng;

pub const TYPE_A: u16 = 1;
pub const CLASS_IN: u16 = 1;
pub const RECURSION_DESIRED: u16 = 1 << 8;

pub trait EncodeBinary {
    fn encode(&self) -> Vec<u8>;
    fn decode(bytes: &[u8]) -> Self;
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsQuery {
    header: DnsHeader,
    question: DnsQuestion,
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

    fn decode(_bytes: &[u8]) -> Self {
        unimplemented!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsQuestion {
    name: Vec<u8>,
    type_: u16,
    class: u16,
}

impl DnsQuestion {
    pub fn new(dns_name: &str, type_: u16, class: u16) -> Self {
        Self {
            name: Self::encode_dns_name(dns_name),
            type_,
            class,
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

    fn decode(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 12);

        // NOTE: The unwraps are safe because the length of `bytes` has been checked
        // by the above assert.
        let id = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        let flags = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        let num_questions = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let num_answers = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
        let num_authorities = u16::from_be_bytes(bytes[8..10].try_into().unwrap());
        let num_additionals = u16::from_be_bytes(bytes[10..12].try_into().unwrap());

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

        self.name.iter().copied().chain(bytes).collect()
    }

    fn decode(bytes: &[u8]) -> Self {
        let bytes_len = bytes.len();

        assert!(bytes_len > 4);

        // Decode the bytes starting from the rear and what ever is left will be shoved into the
        // `name` field. It is asserted that there wil be at least enought bytes to fill both the
        // `type_` and `class` fields, however, it is possible for the `name` field to be have 0
        // length
        // NOTE: The unwraps are safe because the length of `bytes` has been checked
        // by the above assert.
        let type_ = u16::from_be_bytes(bytes[bytes_len - 4..bytes_len - 2].try_into().unwrap());
        let class = u16::from_be_bytes(bytes[bytes_len - 2..].try_into().unwrap());

        let name = bytes[..bytes_len - 4].to_vec();

        Self { name, type_, class }
    }
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

        let decoded_header = DnsHeader::decode(&header.encode());

        assert_eq!(header, decoded_header);
    }

    #[test]
    #[should_panic]
    fn can_panic_on_decoding_invalid_dns_header() {
        let one_byte_short = rand::thread_rng().gen::<[u8; 23]>();

        DnsHeader::decode(&one_byte_short);
    }

    #[test]
    fn can_binary_encode_dns_question() {
        let (name, type_, class) = rand::thread_rng().gen::<([u8; 20], u16, u16)>();

        let question = DnsQuestion {
            name: name.to_vec(),
            type_,
            class,
        };

        let decoded_question = DnsQuestion::decode(&question.encode());

        assert_eq!(question, decoded_question);
    }

    #[test]
    #[should_panic]
    fn can_panic_on_decoding_invalid_dns_question() {
        let one_byte_short = rand::thread_rng().gen::<[u8; 3]>();

        DnsQuestion::decode(&one_byte_short);
    }

    #[test]
    fn can_encode_dns_name() {
        let dns_name = "www.google.com";
        let encoded = DnsQuestion::encode_dns_name(dns_name);

        let expected = vec![
            0x3, 0x77, 0x77, 0x77, 0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d,
            0x0,
        ];

        assert_eq!(encoded, expected);
    }
}
