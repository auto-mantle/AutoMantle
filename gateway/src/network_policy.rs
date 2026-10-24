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
) -> Result<Value> {
    let uuid = crate::linux::new_uuid()?;
    Ok(
        json!({"requestId":uuid,"agentProfileId":profile,"runId":run,"reason":decision.reason(),
        "etherType":meta.ether_type,"protocol":meta.protocol,"sourceIp":meta.source,
        "destinationIp":meta.destination,"sourcePort":meta.source_port,"destinationPort":meta.destination_port,
        "packetCount":packets,"byteCount":bytes}),
    )
}

#[cfg(test)]
mod tests {
    use super::{Decision, NetworkPolicy};
    use crate::sandbox::VmNetwork;

    fn policy() -> NetworkPolicy {
        NetworkPolicy::new(&VmNetwork {
            tap: "tap0".into(),
            host_ip: "10.0.0.1".into(),
            guest_ip: "10.0.0.2".into(),
            guest_mac: "02:00:00:00:00:02".into(),
            host_mac: "02:00:00:00:00:01".into(),
        })
        .unwrap()
    }

    #[test]
    fn arp_requires_the_guest_identity_and_host_target() {
        let mut frame = vec![
            0x02, 0, 0, 0, 0, 1, // destination MAC
            0x02, 0, 0, 0, 0, 2, // source MAC
            0x08, 0x06, // ARP
            0, 1, 0x08, 0, 6, 4, 0, 1, // Ethernet/IPv4 request
            0x02, 0, 0, 0, 0, 2, // sender MAC
            10, 0, 0, 2, // sender IP
            0, 0, 0, 0, 0, 0, // target MAC
            10, 0, 0, 1, // target IP
        ];
        assert_eq!(policy().evaluate(&frame).0, Decision::LinkControl);

        frame[22] = 0x04;
        assert_eq!(policy().evaluate(&frame).0, Decision::Spoofed);
    }

    #[test]
    fn truncated_ethernet_frame_is_malformed() {
        assert_eq!(policy().evaluate(&[0; 13]).0, Decision::Malformed);
    }
}
