use crate::sandbox::{Result, VmNetwork};
use serde_json::{Value, json};
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Metadata {
    pub ether_type: Option<u16>,
    pub protocol: &'static str,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Decision {
    Inspect,
    LinkControl,
    Unsupported,
    Malformed,
    Spoofed,
}
impl Decision {
    pub fn passes(self) -> bool {
        matches!(self, Self::Inspect | Self::LinkControl)
    }
    pub fn reason(self) -> &'static str {
        match self {
            Self::Inspect => "INSPECTION_TRANSPORT",
            Self::LinkControl => "LINK_CONTROL",
            Self::Unsupported => "UNSUPPORTED_NETWORK",
            Self::Malformed => "MALFORMED_NETWORK",
            Self::Spoofed => "SOURCE_BINDING_DENIED",
        }
    }
}
pub struct NetworkPolicy {
    guest_ip: [u8; 4],
    host_ip: [u8; 4],
    guest_mac: [u8; 6],
    host_mac: [u8; 6],
}
fn mac(value: &str) -> Result<[u8; 6]> {
    let mut parts = value.split(':');
    let mut bytes = [0u8; 6];
    for byte in &mut bytes {
        let part = parts.next().ok_or("invalid VM network MAC")?;
        if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid VM network MAC".into());
        }
        *byte = u8::from_str_radix(part, 16)?;
    }
    if parts.next().is_some() {
        return Err("invalid VM network MAC".into());
    }
    Ok(bytes)
}
fn ip(bytes: &[u8]) -> String {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
}
fn be16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}
fn sum(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|b| ((b[0] as u32) << 8) | b.get(1).copied().unwrap_or(0) as u32)
        .sum()
}
fn fold(mut value: u32) -> u16 {
    while value >> 16 != 0 {
        value = (value & 0xffff) + (value >> 16);
    }
    value as u16
}
impl NetworkPolicy {
    pub fn new(network: &VmNetwork) -> Result<Self> {
        Ok(Self {
            guest_ip: network
                .guest_ip
                .parse::<Ipv4Addr>()
                .map_err(|_| "invalid VM guest IP")?
                .octets(),
            host_ip: network
                .host_ip
                .parse::<Ipv4Addr>()
                .map_err(|_| "invalid VM host IP")?
                .octets(),
            guest_mac: mac(&network.guest_mac)?,
            host_mac: mac(&network.host_mac)?,
        })
    }
    pub fn evaluate(&self, frame: &[u8]) -> (Decision, Metadata) {
        let mut meta = Metadata {
            ether_type: None,
            protocol: "UNKNOWN",
            source: None,
            destination: None,
            source_port: None,
            destination_port: None,
        };
        if frame.len() < 14 {
            return (Decision::Malformed, meta);
        }
        let ether_type = be16(frame, 12);
        meta.ether_type = Some(ether_type);
        let payload = &frame[14..];
        let mut decision = Decision::Unsupported;
        match ether_type {
            0x0806 => {
                meta.protocol = "ARP";
                if payload.len() < 28
                    || be16(payload, 0) != 1
                    || be16(payload, 2) != 0x0800
                    || payload[4..6] != [6, 4]
                {
                    return (Decision::Malformed, meta);
                }
                meta.source = Some(ip(&payload[14..18]));
                meta.destination = Some(ip(&payload[24..28]));
                if !matches!(be16(payload, 6), 1 | 2) {
                    return (Decision::Unsupported, meta);
                }
                if payload[8..14] != self.guest_mac || payload[14..18] != self.guest_ip {
                    decision = Decision::Spoofed;
                } else if payload[24..28] == self.host_ip {
                    decision = Decision::LinkControl;
                }
            }
            0x0800 => {
                meta.protocol = "IPV4";
                if payload.len() < 20 || payload[0] >> 4 != 4 {
                    return (Decision::Malformed, meta);
                }
                let header = (payload[0] as usize & 15) * 4;
                let length = be16(payload, 2) as usize;
                if header < 20 || length < header || payload.len() < length {
                    return (Decision::Malformed, meta);
                }
                meta.source = Some(ip(&payload[12..16]));
                meta.destination = Some(ip(&payload[16..20]));
                meta.protocol = match payload[9] {
                    6 => "TCP",
                    17 => "UDP",
                    1 => "ICMP",
                    _ => "IPV4_OTHER",
                };
                if be16(payload, 6) & 0x3fff != 0 {
                    return (Decision::Unsupported, meta);
                }
                let transport = &payload[header..length];
                if matches!(payload[9], 6 | 17) {
                    if transport.len() < if payload[9] == 6 { 20 } else { 8 } {
                        return (Decision::Malformed, meta);
                    }
                    meta.source_port = Some(be16(transport, 0));
                    meta.destination_port = Some(be16(transport, 2));
                    if payload[9] == 6 {
                        let tcp_header = (transport[12] as usize >> 4) * 4;
                        if tcp_header < 20 || tcp_header > transport.len() {
                            return (Decision::Malformed, meta);
                        }
                    }
                }
                if payload[12..16] != self.guest_ip {
                    decision = Decision::Spoofed;
                } else if payload[9] == 6
                    && payload[16..20] == self.host_ip
                    && meta.destination_port == Some(3128)
                    && frame[..6] == self.host_mac
                {
                    if header != 20 || be16(payload, 6) & 0x8000 != 0 {
                        decision = Decision::Unsupported;
                    } else if fold(sum(&payload[..header])) != 0xffff
                        || fold(sum(&payload[12..20]) + 6 + transport.len() as u32 + sum(transport))
                            != 0xffff
                    {
                        decision = Decision::Malformed;
                    } else {
                        decision = Decision::Inspect;
                    }
                }
            }
            0x86dd => {
                meta.protocol = "IPV6";
                if payload.len() < 40 || payload[0] >> 4 != 6 {
                    return (Decision::Malformed, meta);
                }
                let source: [u8; 16] = payload[8..24].try_into().unwrap();
                let destination: [u8; 16] = payload[24..40].try_into().unwrap();
                meta.source = Some(std::net::Ipv6Addr::from(source).to_string());
                meta.destination = Some(std::net::Ipv6Addr::from(destination).to_string());
            }
            0x8100 | 0x88a8 => meta.protocol = "VLAN",
            _ => {}
        }
        if frame[6..12] != self.guest_mac {
            decision = Decision::Spoofed;
        }
        (decision, meta)
    }
}
pub fn audit_event(
    profile: &str,
    run: &str,
    decision: Decision,
    meta: &Metadata,
    packets: u64,
    bytes: u64,
) -> Value {
    let id = crate::linux::new_run_id().expect("host random source unavailable");
    let hex = id.strip_prefix("automantle-vm-").unwrap();
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    json!({"requestId":uuid,"agentProfileId":profile,"runId":run,"reason":decision.reason(),
        "etherType":meta.ether_type,"protocol":meta.protocol,"sourceIp":meta.source,
        "destinationIp":meta.destination,"sourcePort":meta.source_port,"destinationPort":meta.destination_port,
        "packetCount":packets,"byteCount":bytes})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn network() -> VmNetwork {
        VmNetwork {
            tap: "amt-test".into(),
            guest_ip: "10.253.0.2".into(),
            host_ip: "10.253.0.1".into(),
            guest_mac: "02:00:00:00:00:02".into(),
            host_mac: "02:00:00:00:00:01".into(),
        }
    }
    #[test]
    fn malformed_network_configuration_is_rejected() {
        let mut invalid = network();
        invalid.guest_ip = "not-an-ip".into();
        assert!(NetworkPolicy::new(&invalid).is_err());
        invalid = network();
        invalid.host_mac = "02:00:00:00:00:gg".into();
        assert!(NetworkPolicy::new(&invalid).is_err());
        invalid.host_mac = "02:00:00:00:00".into();
        assert!(NetworkPolicy::new(&invalid).is_err());
    }
    fn frame(kind: u16) -> Vec<u8> {
        let mut bytes = vec![0; 14];
        bytes[..6].copy_from_slice(&mac(&network().host_mac).unwrap());
        bytes[6..12].copy_from_slice(&mac(&network().guest_mac).unwrap());
        bytes[12..14].copy_from_slice(&kind.to_be_bytes());
        bytes
    }
    fn tcp(destination: [u8; 4], port: u16) -> Vec<u8> {
        let mut bytes = frame(0x0800);
        let mut ip = vec![0; 40];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&40u16.to_be_bytes());
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[10, 253, 0, 2]);
        ip[16..20].copy_from_slice(&destination);
        ip[20..22].copy_from_slice(&50000u16.to_be_bytes());
        ip[22..24].copy_from_slice(&port.to_be_bytes());
        ip[32] = 0x50;
        let tcp_checksum = !fold(sum(&ip[12..20]) + 6 + 20 + sum(&ip[20..]));
        ip[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
        let ip_checksum = !fold(sum(&ip[..20]));
        ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        bytes.extend(ip);
        bytes
    }
    #[test]
    fn only_inspection_transport_passes_not_direct_or_management_traffic() {
        let p = NetworkPolicy::new(&network()).unwrap();
        assert_eq!(p.evaluate(&tcp([10, 253, 0, 1], 3128)).0, Decision::Inspect);
        for (ip, port) in [
            ([1, 1, 1, 1], 443),
            ([10, 253, 0, 1], 8082),
            ([10, 253, 0, 1], 53),
        ] {
            let (decision, meta) = p.evaluate(&tcp(ip, port));
            assert_eq!(decision, Decision::Unsupported);
            assert_eq!(meta.destination_port, Some(port));
        }
        let mut spoof = tcp([10, 253, 0, 1], 3128);
        spoof[6] = 4;
        assert_eq!(p.evaluate(&spoof).0, Decision::Spoofed);
    }
    #[test]
    fn proxy_transport_denies_routing_options_and_invalid_checksums_in_policy() {
        let p = NetworkPolicy::new(&network()).unwrap();
        let valid = tcp([10, 253, 0, 1], 3128);
        let mut bad_ip = valid.clone();
        bad_ip[24] ^= 1;
        assert_eq!(p.evaluate(&bad_ip).0, Decision::Malformed);
        let mut bad_tcp = valid.clone();
        bad_tcp[49] ^= 1;
        assert_eq!(p.evaluate(&bad_tcp).0, Decision::Malformed);
        let mut routed = valid[..34].to_vec();
        routed.extend([137, 7, 4, 1, 1, 1, 1, 0]);
        routed.extend_from_slice(&valid[34..]);
        routed[14] = 0x47;
        routed[16..18].copy_from_slice(&48u16.to_be_bytes());
        assert_eq!(p.evaluate(&routed).0, Decision::Unsupported);
    }

    #[test]
    fn all_ether_types_and_malformed_bytes_receive_a_decision() {
        let p = NetworkPolicy::new(&network()).unwrap();
        for ether in 0..=u16::MAX {
            let (decision, meta) = p.evaluate(&frame(ether));
            assert!(!decision.passes());
            assert_eq!(meta.ether_type, Some(ether));
        }
        for length in 0..14 {
            assert_eq!(p.evaluate(&vec![0; length]).0, Decision::Malformed);
        }
    }
    #[test]
    fn arp_is_explicit_link_policy_not_an_unchecked_exception() {
        let p = NetworkPolicy::new(&network()).unwrap();
        let mut bytes = frame(0x0806);
        let mut arp = vec![0; 28];
        arp[1] = 1;
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[7] = 1;
        arp[8..14].copy_from_slice(&mac(&network().guest_mac).unwrap());
        arp[14..18].copy_from_slice(&[10, 253, 0, 2]);
        arp[24..28].copy_from_slice(&[10, 253, 0, 1]);
        bytes.extend(arp);
        assert_eq!(p.evaluate(&bytes).0, Decision::LinkControl);
        bytes[41] = 99;
        assert!(!p.evaluate(&bytes).0.passes());
    }
}
