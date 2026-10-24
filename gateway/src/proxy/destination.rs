use super::{Context, Result};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static RESOLVERS: AtomicUsize = AtomicUsize::new(0);
pub(super) fn resolve(host: &str, port: u16, context: &Context) -> Result<Vec<SocketAddr>> {
    RESOLVERS
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < 16).then_some(n + 1)
        })
        .map_err(|_| "DNS request limit reached")?;
    let host = host.to_owned();
    let (sender, receiver) = std::sync::mpsc::channel();
    let spawned = thread::Builder::new().spawn(move || {
        let result = (host.as_str(), port)
            .to_socket_addrs()
            .map(|a| a.collect::<Vec<_>>());
        RESOLVERS.fetch_sub(1, Ordering::SeqCst);
        let _ = sender.send(result);
    });
    if spawned.is_err() {
        RESOLVERS.fetch_sub(1, Ordering::SeqCst);
        return Err("could not start DNS resolver".into());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while context.active() && Instant::now() < deadline {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(result) => return Ok(result?),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => break,
        }
    }
    Err("DNS timed out or cancelled".into())
}

pub(super) fn parse_target(target: &str) -> Option<(String, String, String)> {
    let (host, origin) = http_origin(target)?;
    let path = origin.split('?').next()?.to_owned();
    Some((host, path, origin))
}
pub(super) fn http_origin(target: &str) -> Option<(String, String)> {
    let rest = target.strip_prefix("http://")?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let host = rest[..end].to_ascii_lowercase();
    let path = if end == rest.len() {
        "/".to_owned()
    } else if rest.as_bytes()[end] == b'?' {
        format!("/{}", &rest[end..])
    } else {
        rest[end..].to_owned()
    };
    (!host.is_empty() && path.starts_with('/')).then_some((host, path))
}

pub(super) fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 198 && b == 18)
                || (a == 198 && b == 19)
                || (a == 198 && b == 51 && c == 100)
                || (a == 192 && b == 88 && c == 99)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224
                || (a == 255 && b == 255 && c == 255 && d == 255))
        }
        IpAddr::V6(_) => false,
    }
}

pub(super) fn public_ipv4_destinations(mut addresses: Vec<SocketAddr>) -> Option<Vec<SocketAddr>> {
    addresses.retain(SocketAddr::is_ipv4);
    (!addresses.is_empty() && addresses.iter().all(|address| public_address(address.ip())))
        .then_some(addresses)
}

#[cfg(test)]
mod tests {
    use super::{public_address, public_ipv4_destinations};

    #[test]
    fn special_use_destinations_are_blocked() {
        for address in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.0.0.9"] {
            assert!(!public_address(address.parse().unwrap()));
        }
        assert!(public_address("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn mixed_public_and_private_dns_answers_are_rejected() {
        let addresses = vec![
            "8.8.8.8:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ];
        assert!(public_ipv4_destinations(addresses).is_none());
    }
}
