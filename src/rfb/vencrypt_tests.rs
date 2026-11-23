use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::{self, JoinHandle};

use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslMethod};
use openssl::x509::{X509, X509NameBuilder};

use super::backend::{self, DialHandle};
use super::handshake::RfbFailure;
use super::policy::{FINGERPRINT_KEY, TLS_KEY};
use super::server_fixture::FIXTURE_TIMEOUT;
use super::wire;
use crate::model::{ConnectionProfile, Protocol};
use crate::state_machine::SessionEvent;

const USER: &str = "sharing-üser";
const PASSWORD: &str = "synthetic-credential";

fn tls_identity() -> (SslAcceptor, String) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "sharing.invalid").unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = cert.build();
    let fingerprint = cert
        .digest(MessageDigest::sha256())
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    // Unread session tickets can turn the client's close into a TCP reset.
    acceptor.set_num_tickets(0).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    acceptor.set_private_key(&key).unwrap();
    (acceptor.build(), fingerprint)
}

fn start_server(
    subtype: u32,
    after_offer: impl FnOnce(std::net::TcpStream) + Send + 'static,
) -> (ConnectionProfile, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut profile = ConnectionProfile::new("fixture", Protocol::Vnc, "127.0.0.1");
    profile.port = listener.local_addr().unwrap().port();
    profile.username = USER.into();
    profile.extra.insert(TLS_KEY.into(), "true".into());
    let worker = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
        socket.set_write_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
        socket.write_all(wire::RFB_003_008).unwrap();
        assert_eq!(read::<12>(&mut socket), *wire::RFB_003_008);
        socket.write_all(&[3, 1, 2, 19]).unwrap();
        assert_eq!(read::<1>(&mut socket), [19]);
        socket.write_all(&[0, 2]).unwrap();
        assert_eq!(read::<2>(&mut socket), [0, 2]);
        socket.write_all(&[0, 1]).unwrap();
        socket.write_all(&subtype.to_be_bytes()).unwrap();
        after_offer(socket);
    });
    (profile, worker)
}

fn read<const N: usize>(stream: &mut impl Read) -> [u8; N] {
    let mut bytes = [0; N];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}

fn accept_x509_plain(mut socket: std::net::TcpStream) -> std::net::TcpStream {
    assert_eq!(u32::from_be_bytes(read(&mut socket)), 262);
    socket.write_all(&[1]).unwrap();
    socket
}

fn assert_no_application_data(mut tls: openssl::ssl::SslStream<std::net::TcpStream>) {
    match tls.read(&mut [0]) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
        other => panic!("expected TLS connection to close without application data, got {other:?}"),
    }
}

#[test]
fn pinned_wayvnc_sends_utf8_credentials_and_reaches_ready() {
    let (server, fingerprint) = tls_identity();
    let (mut profile, thread) = start_server(262, move |socket| {
        let mut tls = server.accept(accept_x509_plain(socket)).unwrap();
        assert_eq!(u32::from_be_bytes(read(&mut tls)) as usize, USER.len());
        assert_eq!(u32::from_be_bytes(read(&mut tls)) as usize, PASSWORD.len());
        assert_eq!(read::<{ USER.len() }>(&mut tls), USER.as_bytes());
        assert_eq!(read::<{ PASSWORD.len() }>(&mut tls), PASSWORD.as_bytes());
        tls.write_all(&0u32.to_be_bytes()).unwrap();
        assert_eq!(read::<1>(&mut tls), [1]);
        let mut init = [0; wire::SERVER_INIT_PREFIX_BYTES];
        init[..4].copy_from_slice(&[0, 64, 0, 64]);
        init[4..20].copy_from_slice(&wire::set_pixel_format()[4..]);
        tls.write_all(&init).unwrap();
        assert_eq!(read::<20>(&mut tls), wire::set_pixel_format().as_slice());
        let mut encodings = vec![0; wire::set_encodings().len()];
        tls.read_exact(&mut encodings).unwrap();
        assert_eq!(encodings, wire::set_encodings());
        assert_eq!(
            read::<10>(&mut tls),
            wire::framebuffer_update_request(false, 64, 64)
        );
    });
    profile.extra.insert(FINGERPRINT_KEY.into(), fingerprint);
    let (session, _, events, _stream) =
        backend::open_on_with_password(&profile, 1, &DialHandle::new(), Some(PASSWORD)).unwrap();
    assert_eq!(events, [SessionEvent::Ready]);
    thread.join().unwrap();
    session.close();
}

#[test]
fn a_certificate_mismatch_prevents_credentials_even_after_the_tls_handshake() {
    let (server, _) = tls_identity();
    let (mut profile, thread) = start_server(262, move |socket| {
        assert_no_application_data(server.accept(accept_x509_plain(socket)).unwrap());
    });
    profile
        .extra
        .insert(FINGERPRINT_KEY.into(), "00".repeat(32));
    let error = backend::open_on_with_password(&profile, 1, &DialHandle::new(), Some(PASSWORD))
        .unwrap_err();
    assert!(matches!(error, RfbFailure::Tls(reason) if reason.contains("does not match")));
    thread.join().unwrap();
}

#[test]
fn overlong_x509_plain_credentials_send_no_partial_message() {
    let (server, fingerprint) = tls_identity();
    let (mut profile, thread) = start_server(262, move |socket| {
        assert_no_application_data(server.accept(accept_x509_plain(socket)).unwrap());
    });
    profile.extra.insert(FINGERPRINT_KEY.into(), fingerprint);
    let error =
        backend::open_on_with_password(&profile, 1, &DialHandle::new(), Some(&"x".repeat(4097)))
            .unwrap_err();
    assert!(matches!(error, RfbFailure::Tls(reason) if reason.contains("4096 bytes")));
    thread.join().unwrap();
}

#[test]
fn without_a_pin_the_system_trust_check_rejects_the_self_signed_certificate() {
    let (server, _) = tls_identity();
    let (profile, thread) = start_server(262, move |socket| {
        assert!(server.accept(accept_x509_plain(socket)).is_err());
    });
    let error = backend::open_on_with_password(&profile, 1, &DialHandle::new(), Some(PASSWORD))
        .unwrap_err();
    assert!(matches!(error, RfbFailure::Tls(reason) if reason.contains("trusted CA")));
    thread.join().unwrap();
}

#[test]
fn verified_tls_refuses_the_anonymous_tls_plain_subtype() {
    let (profile, thread) = start_server(259, |mut socket| {
        assert_eq!(socket.read(&mut [0]).unwrap(), 0);
    });
    let error = backend::open_on_with_password(&profile, 1, &DialHandle::new(), Some(PASSWORD))
        .unwrap_err();
    assert!(matches!(error, RfbFailure::Tls(reason) if reason.contains("must offer X509Plain")));
    thread.join().unwrap();
}
