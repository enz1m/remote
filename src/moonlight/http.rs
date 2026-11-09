use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use moonlight_common::error::Error;
use moonlight_common::http::{
    ClientInfo, Endpoint, QueryBuilder, QueryBuilderError, QueryParam, Request, TextResponse,
    client::blocking_client::RequestClient,
};
use openssl::pkey::PKey;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use pem::Pem;

use crate::desktop_worker::Control;

thread_local! { static ACTIVE: RefCell<Option<(Arc<Control>, bool)>> = const { RefCell::new(None) }; }
pub(super) fn bind(control: &Arc<Control>, allow_resume: bool) {
    ACTIVE.with(|active| *active.borrow_mut() = Some((Arc::clone(control), allow_resume)));
}
pub(super) fn unbind() {
    ACTIVE.with(|active| active.borrow_mut().take());
}

#[derive(Clone)]
pub(super) struct PinnedClient {
    tls: Option<SslConnector>,
    timeout: Duration,
    control: Option<Arc<Control>>,
    allow_resume: bool,
}
fn error() -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Moonlight's bounded authenticated HTTP request failed",
    ))
}

struct Query(Vec<(String, String)>);
impl QueryBuilder for Query {
    fn append(&mut self, parameter: QueryParam) -> Result<(), QueryBuilderError> {
        self.0.push((parameter.key.into(), parameter.value.into()));
        Ok(())
    }
}

impl PinnedClient {
    fn new(timeout: Duration) -> Self {
        Self {
            tls: None,
            timeout,
            control: ACTIVE.with(|active| {
                active
                    .borrow()
                    .as_ref()
                    .map(|(control, _)| Arc::clone(control))
            }),
            allow_resume: ACTIVE
                .with(|active| active.borrow().as_ref().is_some_and(|(_, allow)| *allow)),
        }
    }
    fn fetch<E: Endpoint>(
        &self,
        secure: bool,
        info: ClientInfo,
        hostport: &str,
        request: &E::Request,
    ) -> Result<Vec<u8>, Error> {
        // A racing launch may resume only with the profile's explicit host-session consent.
        if E::path() == "/resume" && !self.allow_resume {
            return Err(Error::Unauthenticated);
        }
        if hostport.contains(['\r', '\n', '/', '@']) {
            return Err(error());
        }
        let mut query = Query(Vec::new());
        info.append_query_params(&mut query).map_err(|_| error())?;
        request
            .append_query_params(&mut query)
            .map_err(|_| error())?;
        let query = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(query.0)
            .finish();
        if query.len() > 16 * 1024 {
            return Err(error());
        }
        let endpoint = hostport
            .to_socket_addrs()
            .map_err(|_| error())?
            .next()
            .ok_or_else(error)?;
        let mut socket =
            TcpStream::connect_timeout(&endpoint, Duration::from_secs(5)).map_err(|_| error())?;
        if let Some(control) = &self.control {
            control.adopt(&socket).map_err(|_| error())?;
        }
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|_| error())?;
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| error())?;
        let header = format!(
            "GET {}?{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
            E::path(),
            query,
            hostport
        );
        if secure {
            let host = hostport
                .rsplit_once(':')
                .ok_or_else(error)?
                .0
                .trim_start_matches('[')
                .trim_end_matches(']');
            let mut configuration = self
                .tls
                .as_ref()
                .ok_or(Error::Unauthenticated)?
                .configure()
                .map_err(|_| error())?;
            // Pairing authenticates the exact leaf certificate rather than its hostname or issuer.
            configuration.set_verify_hostname(false);
            let mut stream = configuration
                .connect(host, socket)
                .map_err(|_| Error::Unauthenticated)?;
            stream.write_all(header.as_bytes()).map_err(|_| error())?;
            read_response(&mut stream)
        } else {
            if E::https_required() {
                return Err(Error::Unauthenticated);
            }
            socket.write_all(header.as_bytes()).map_err(|_| error())?;
            read_response(&mut socket)
        }
    }
}

impl RequestClient for PinnedClient {
    fn with_defaults() -> Result<Self, Error> {
        Ok(Self::new(Duration::from_secs(10)))
    }
    fn with_defaults_long_timeout() -> Result<Self, Error> {
        Ok(Self::new(Duration::from_secs(90)))
    }
    fn with_certificates(private: &Pem, certificate: &Pem, server: &Pem) -> Result<Self, Error> {
        let mut tls = SslConnector::builder(SslMethod::tls_client()).map_err(|_| error())?;
        tls.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
            .map_err(|_| error())?;
        let certificate = X509::from_der(certificate.contents()).map_err(|_| error())?;
        tls.set_certificate(&certificate).map_err(|_| error())?;
        let private_key =
            PKey::private_key_from_pem(private.to_string().as_bytes()).map_err(|_| error())?;
        tls.set_private_key(&private_key).map_err(|_| error())?;
        tls.check_private_key().map_err(|_| error())?;
        let expected = server.contents().to_vec();
        tls.set_verify_depth(4);
        tls.set_verify_callback(SslVerifyMode::PEER, move |_, context| {
            context.error_depth() != 0
                || context
                    .current_cert()
                    .and_then(|certificate| certificate.to_der().ok())
                    .is_some_and(|actual| actual == expected)
        });
        let mut client = Self::new(Duration::from_secs(10));
        client.tls = Some(tls.build());
        Ok(client)
    }
    fn send_http<E>(
        &self,
        info: ClientInfo,
        address: &str,
        request: &E::Request,
    ) -> Result<E::Response, Error>
    where
        E: Endpoint,
        E::Response: TextResponse,
    {
        let body = self.fetch::<E>(false, info, address, request)?;
        E::Response::from_str(std::str::from_utf8(&body).map_err(|_| error())?)
    }
    fn send_https<E>(
        &self,
        info: ClientInfo,
        address: &str,
        request: &E::Request,
    ) -> Result<E::Response, Error>
    where
        E: Endpoint,
        E::Response: TextResponse,
    {
        let body = self.fetch::<E>(true, info, address, request)?;
        E::Response::from_str(std::str::from_utf8(&body).map_err(|_| error())?)
    }
    fn send_https_with_bytes<E>(
        &self,
        info: ClientInfo,
        address: &str,
        request: &E::Request,
    ) -> Result<E::Response, Error>
    where
        E: Endpoint<Response = Vec<u8>>,
    {
        self.fetch::<E>(true, info, address, request)
    }
}

fn read_more(stream: &mut impl Read, bytes: &mut Vec<u8>) -> Result<usize, Error> {
    let mut buffer = [0; 8192];
    let n = stream.read(&mut buffer).map_err(|_| error())?;
    if bytes.len().saturating_add(n) > 1024 * 1024 + 32 * 1024 {
        return Err(error());
    }
    bytes.extend_from_slice(&buffer[..n]);
    Ok(n)
}
fn read_response(stream: &mut impl Read) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    let (end, length, chunked) = loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(&bytes).map_err(|_| error())? {
            httparse::Status::Partial => {
                if bytes.len() > 32 * 1024 || read_more(stream, &mut bytes)? == 0 {
                    return Err(error());
                }
            }
            httparse::Status::Complete(end) => {
                if response.code != Some(200) {
                    return Err(error());
                }
                let mut length = None;
                let mut chunked = false;
                for header in response.headers {
                    if header.name.eq_ignore_ascii_case("content-length") {
                        if length.is_some() {
                            return Err(error());
                        }
                        length = Some(
                            std::str::from_utf8(header.value)
                                .map_err(|_| error())?
                                .trim()
                                .parse::<usize>()
                                .map_err(|_| error())?,
                        );
                    }
                    if header.name.eq_ignore_ascii_case("transfer-encoding") {
                        if !header.value.eq_ignore_ascii_case(b"chunked") {
                            return Err(error());
                        }
                        chunked = true;
                    }
                }
                if length.is_some_and(|n| n > 1024 * 1024) || (length.is_some() && chunked) {
                    return Err(error());
                }
                break (end, length, chunked);
            }
        }
    };
    if chunked {
        return chunks(stream, bytes[end..].to_vec());
    }
    if let Some(length) = length {
        while bytes.len() - end < length {
            if read_more(stream, &mut bytes)? == 0 {
                return Err(error());
            }
        }
        return Ok(bytes[end..end + length].to_vec());
    }
    while read_more(stream, &mut bytes)? != 0 {}
    if bytes.len() - end > 1024 * 1024 {
        return Err(error());
    }
    Ok(bytes[end..].to_vec())
}
fn chunks(stream: &mut impl Read, mut bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut offset = 0;
    for _ in 0..4096 {
        let end = loop {
            if let Some(n) = bytes[offset..].windows(2).position(|w| w == b"\r\n") {
                break offset + n;
            }
            if bytes.len() - offset > 8192 || read_more(stream, &mut bytes)? == 0 {
                return Err(error());
            }
        };
        let size = std::str::from_utf8(&bytes[offset..end])
            .map_err(|_| error())?
            .split(';')
            .next()
            .ok_or_else(error)?;
        let size = usize::from_str_radix(size, 16).map_err(|_| error())?;
        offset = end + 2;
        if size == 0 {
            while bytes.len().saturating_sub(offset) < 2 {
                if read_more(stream, &mut bytes)? == 0 {
                    return Err(error());
                }
            }
            if &bytes[offset..offset + 2] != b"\r\n" {
                return Err(error());
            }
            return Ok(output);
        }
        if size > 1024 * 1024 || output.len().saturating_add(size) > 1024 * 1024 {
            return Err(error());
        }
        while bytes.len().saturating_sub(offset) < size + 2 {
            if read_more(stream, &mut bytes)? == 0 {
                return Err(error());
            }
        }
        if &bytes[offset + size..offset + size + 2] != b"\r\n" {
            return Err(error());
        }
        output.extend_from_slice(&bytes[offset..offset + size]);
        offset += size + 2;
    }
    Err(error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_consent_is_checked_again_before_any_network_request() {
        struct Resume;
        impl Endpoint for Resume {
            type Request = ClientInfo;
            type Response = ();
            fn path() -> &'static str {
                "/resume"
            }
            fn https_required() -> bool {
                true
            }
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let mut client = PinnedClient::new(Duration::from_secs(1));
        assert!(matches!(
            client.fetch::<Resume>(
                true,
                ClientInfo::default(),
                &address,
                &ClientInfo::default()
            ),
            Err(Error::Unauthenticated)
        ));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        client.allow_resume = true;
        assert!(matches!(
            client.fetch::<Resume>(
                true,
                ClientInfo::default(),
                &address,
                &ClientInfo::default()
            ),
            Err(Error::Unauthenticated)
        ));
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        assert_eq!(tcp.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn paired_leaf_pin_accepts_its_host_and_rejects_replacement_before_http() {
        use moonlight_common::crypto::openssl::OpenSSLCryptoBackend;
        use moonlight_common::http::pair::PairingCryptoBackend;
        use openssl::ssl::SslAcceptor;
        use std::net::TcpListener;
        let crypto = OpenSSLCryptoBackend;
        let (client_cert, client_key) = crypto.generate_client_identity().unwrap();
        let (other_cert, other_key) = crypto.generate_client_identity().unwrap();
        for trusted in [true, false] {
            let (cert, key) = if trusted {
                (&client_cert, &client_key)
            } else {
                (&other_cert, &other_key)
            };
            let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls_server()).unwrap();
            acceptor
                .set_certificate(&X509::from_der(cert.to_pem().contents()).unwrap())
                .unwrap();
            acceptor
                .set_private_key(
                    &PKey::private_key_from_pem(key.to_pem().to_string().as_bytes()).unwrap(),
                )
                .unwrap();
            let acceptor = acceptor.build();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (tcp, _) = listener.accept().unwrap();
                tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                if let Ok(mut stream) = acceptor.accept(tcp) {
                    let result = stream.read(&mut [0; 1]);
                    if trusted {
                        assert_eq!(result.unwrap(), 1);
                    } else {
                        assert!(!matches!(result, Ok(n) if n > 0));
                    }
                } else {
                    assert!(!trusted);
                }
            });
            let client = PinnedClient::with_certificates(
                &client_key.to_pem(),
                &client_cert.to_pem(),
                &client_cert.to_pem(),
            )
            .unwrap();
            let mut config = client.tls.unwrap().configure().unwrap();
            config.set_verify_hostname(false);
            let result = config.connect("fixture", TcpStream::connect(address).unwrap());
            if trusted {
                result.unwrap().write_all(b"G").unwrap();
            } else {
                assert!(result.is_err());
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn bounded_http_rejects_ambiguous_truncated_and_oversized_bodies() {
        for bytes in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                .as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\na",
            b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n",
        ] {
            assert!(read_response(&mut std::io::Cursor::new(bytes)).is_err());
        }
        assert_eq!(
            read_response(&mut std::io::Cursor::new(
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"
            ))
            .unwrap(),
            b"abc"
        );
        assert_eq!(
            read_response(&mut std::io::Cursor::new(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
            ))
            .unwrap(),
            b"abc"
        );
    }
}
