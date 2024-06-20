# RDNS: Rust DNS

This is a toy implmentation of a DNS resolver based on [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035).
During the implementation, I loosely followed and referenced Julia Evans' tutorial
[Implement DNS in a Weekend](https://jvns.ca/blog/2023/05/12/introducing-implement-dns-in-a-weekend/).
The final output of the program is modelled after the output of the
[dig](https://gitlab.isc.org/isc-projects/bind9/-/tree/main) utility.

## Usage

The basic usage of the resolver is as follows where `<domain-name>` is a valid
domain name according to [RFC 1035 2.3.1](https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.1):

```
rdns <domain-name>
```

The user can also specify the DNS server used to query from as follows where
`<server-ip>` is a valid IPV4 address:

```
rdns @<server-ip> <domain-name>
```

## RDATA formats supported

- [x] A
- [x] NS
- [ ] MD
- [ ] MF
- [x] CNAME
- [x] SOA
- [ ] MB
- [ ] MG
- [ ] MR
- [ ] NULL
- [ ] WKS
- [ ] PTR
- [ ] HINFO
- [ ] MINFO
- [ ] MX
- [x] TXT
- [x] AAAA ([RFC 1886](https://www.rfc-editor.org/rfc/rfc1886))

## Todos

- [x] Basic domain name resolution
- [x] Request timeouts
- [ ] Caching
- [ ] Rich cli experience
  - [ ] Selection of query type and class from cli
  - [ ] Allowing multiple DNS servers to be specified from the cli
