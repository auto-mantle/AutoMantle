use crate::{sandbox::Result, transport::Socket};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, StreamOwned,
    pki_types::{PrivateKeyDer, ServerName},
    server::Acceptor,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Component, Path},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use time::OffsetDateTime;
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

pub type Downstream = StreamOwned<rustls::ServerConnection, Socket>;
pub type Upstream = StreamOwned<ClientConnection, Socket>;
const MAX_FILE: u64 = 32 * 1024;

struct Issuer {
    key: KeyPair,
    certificate: Certificate,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    cache: BTreeMap<String, Arc<ServerConfig>>,
}
pub struct Tls {
    issuer: Mutex<Issuer>,
    upstream: Arc<ClientConfig>,
    deadline: Instant,
}

fn parent(path: &Path) -> Result<(File, CString)> {
    if !path.is_absolute() {
        return Err("TLS paths must be absolute".into());
    }
    let mut parts = path.components().skip(1).collect::<Vec<_>>();
    let leaf = match parts.pop() {
        Some(Component::Normal(name)) => CString::new(name.as_bytes())?,
        _ => return Err("invalid TLS file path".into()),
    };
    let mut directory = File::open("/")?;
    for component in parts {
        let Component::Normal(name) = component else {
            return Err("invalid TLS path component".into());
        };
        let name = CString::new(name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        directory = unsafe { File::from_raw_fd(fd) };
        let meta = directory.metadata()?;
        if ![0, unsafe { libc::geteuid() }].contains(&meta.uid()) || meta.mode() & 0o022 != 0 {
            return Err(
                "TLS parent directories must be root- or gateway-owned and not writable by others"
                    .into(),
            );
        }
    }
    Ok((directory, leaf))
}
pub(crate) fn protected_read(path: &Path, private: bool) -> Result<String> {
    let (directory, name) = parent(path)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.len() > MAX_FILE
        || meta.mode() & (if private { 0o077 } else { 0o022 }) != 0
    {
        return Err(
            "TLS files must be bounded gateway-owned regular files with protected permissions"
                .into(),
        );
    }
    let mut bytes = Vec::new();
    (&mut file).take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE {
        return Err("TLS file too large".into());
    }
    Ok(String::from_utf8(bytes)?)
}
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}
fn upstream_config(roots: RootCertStore) -> Result<Arc<ClientConfig>> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}
impl Tls {
    pub fn load(path: &Path, deadline: Instant) -> Result<Self> {
        let value: Value = serde_json::from_str(&protected_read(path, true)?)?;
        let fields = value.as_object().ok_or("invalid TLS configuration")?;
        if fields.len() != 2
            || fields
                .keys()
                .any(|key| !["caCertificate", "caPrivateKey"].contains(&key.as_str()))
        {
            return Err("TLS configuration requires only caCertificate and caPrivateKey".into());
        }
        let field = |name| value[name].as_str().ok_or("missing TLS path");
        let pem = protected_read(Path::new(field("caCertificate")?), false)?;
        let key = protected_read(Path::new(field("caPrivateKey")?), true)?;
        Self::from_pem(&pem, &key, deadline)
    }
    pub(crate) fn from_pem(pem: &str, key: &str, deadline: Instant) -> Result<Self> {
        let certificates =
            rustls_pemfile::certs(&mut pem.as_bytes()).collect::<std::io::Result<Vec<_>>>()?;
        if certificates.len() != 1 {
            return Err("expected exactly one self-signed gateway CA certificate".into());
        }
        let (remaining, parsed) = X509Certificate::from_der(certificates[0].as_ref())
            .map_err(|_| "invalid CA certificate")?;
        if !remaining.is_empty()
            || !parsed.validity().is_valid()
            || parsed.subject() != parsed.issuer()
        {
            return Err("CA must be currently valid and self-signed".into());
        }
        parsed
            .verify_signature(None)
            .map_err(|_| "invalid CA signature")?;
        let constraints = parsed
            .basic_constraints()?
            .ok_or("CA basic constraints required")?;
        let usage = parsed.key_usage()?.ok_or("CA signing usage required")?;
        if !constraints.value.ca || !usage.value.key_cert_sign() {
            return Err("certificate is not authorized to sign".into());
        }
        if let Some(usage) = parsed.extended_key_usage()? {
            if !usage.value.any && !usage.value.server_auth {
                return Err("CA does not permit server authentication".into());
            }
        }
        let key = KeyPair::from_pem(key)?;
        if key.public_key_der() != parsed.public_key().raw {
            return Err("CA private key does not match certificate".into());
        }
        let not_before =
            OffsetDateTime::from_unix_timestamp(parsed.validity().not_before.timestamp())?;
        let not_after =
            OffsetDateTime::from_unix_timestamp(parsed.validity().not_after.timestamp())?;
        let mut params = CertificateParams::from_ca_cert_pem(pem)?;
        params.not_before = not_before;
        params.not_after = not_after;
        let certificate = params.self_signed(&key)?;
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Ok(Self {
            issuer: Mutex::new(Issuer {
                key,
                certificate,
                not_before,
                not_after,
                cache: BTreeMap::new(),
            }),
            upstream: upstream_config(roots)?,
            deadline,
        })
    }
    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let mut issuer = self.issuer.lock().map_err(|_| "CA lock failed")?;
        let now = OffsetDateTime::now_utc();
        if now < issuer.not_before || now >= issuer.not_after || Instant::now() >= self.deadline {
            return Err("CA or VM lifetime expired".into());
        }
        if let Some(config) = issuer.cache.get(host) {
            return Ok(Arc::clone(config));
        }
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.not_before = (now - time::Duration::minutes(5)).max(issuer.not_before);
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        params.not_after = (now
            + time::Duration::seconds(remaining.as_secs().max(1).min(86400) as i64))
        .min(issuer.not_after);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate()?;
        let certificate = params.signed_by(&key, &issuer.certificate, &issuer.key)?;
        let private = PrivateKeyDer::Pkcs8(key.serialize_der().into());
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], private)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        let config = Arc::new(config);
        if issuer.cache.len() >= 64 {
            issuer.cache.pop_first();
        }
        issuer.cache.insert(host.to_owned(), Arc::clone(&config));
        Ok(config)
    }
    pub fn accept(&self, mut socket: Socket, host: &str) -> Result<Downstream> {
        socket.phase(Duration::from_secs(10));
        let mut acceptor = Acceptor::default();
        let accepted = loop {
            if acceptor.read_tls(&mut socket)? == 0 {
                return Err("TLS client closed".into());
            }
            match acceptor.accept() {
                Ok(Some(accepted)) => break accepted,
                Ok(None) => {}
                Err(_) => return Err("invalid TLS ClientHello".into()),
            }
        };
        let hello = accepted.client_hello();
        if !hello
            .server_name()
            .is_some_and(|name| name.eq_ignore_ascii_case(host))
        {
            return Err("CONNECT and TLS SNI must match".into());
        }
        if hello
            .alpn()
            .is_some_and(|mut protocols| !protocols.any(|p| p == b"http/1.1"))
        {
            return Err("only HTTP/1.1 TLS negotiation is supported".into());
        }
        let mut connection = accepted
            .into_connection(self.server_config(host)?)
            .map_err(|_| "TLS configuration rejected ClientHello")?;
        while connection.is_handshaking() {
            connection.complete_io(&mut socket)?;
        }
        socket.phase(Duration::from_secs(10));
        Ok(StreamOwned::new(connection, socket))
    }
    pub fn connect(&self, mut socket: Socket, host: &str) -> Result<Upstream> {
        socket.phase(Duration::from_secs(10));
        let mut connection = ClientConnection::new(
            Arc::clone(&self.upstream),
            ServerName::try_from(host.to_owned())?,
        )?;
        while connection.is_handshaking() {
            connection.complete_io(&mut socket)?;
        }
        if connection.alpn_protocol().is_some_and(|p| p != b"http/1.1") {
            return Err("unsupported upstream TLS protocol".into());
        }
        socket.phase(Duration::from_secs(60));
        Ok(StreamOwned::new(connection, socket))
    }
}

pub fn initialize(directory: &Path) -> Result<()> {
    let (_parent, _name) = parent(directory)?;
    let mut builder = fs::DirBuilder::new();
    use std::os::unix::fs::DirBuilderExt;
    builder.mode(0o700).create(directory)?;
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::days(365 * 3);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Automantle Gateway Local CA");
    params.distinguished_name = name;
    let certificate = params.self_signed(&key)?;
    let save = |name: &str, contents: &str, mode| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(directory.join(name))?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(directory.join(name), fs::Permissions::from_mode(mode))?;
        Ok(())
    };
    save("ca-key.pem", &key.serialize_pem(), 0o600)?;
    save("ca.pem", &certificate.pem(), 0o644)?;
    save(
        "tls.json",
        &serde_json::to_string_pretty(&json!({
            "caCertificate": directory.join("ca.pem"),
            "caPrivateKey": directory.join("ca-key.pem"),
        }))?,
        0o600,
    )?;
    File::open(directory)?.sync_all()?;
    println!("Public guest CA: {}", directory.join("ca.pem").display());
    println!(
        "Host TLS configuration: {}",
        directory.join("tls.json").display()
    );
    Ok(())
}
