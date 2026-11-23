//! Who may be dialled in plaintext, decided from resolved addresses. Pure
//! functions over a `SocketAddr` list and a profile, so mixed loopback/routable
//! names, IPv4-mapped loopback and near-miss acknowledgements need no resolver.

use super::*;
use std::net::{Ipv4Addr, SocketAddr};

fn profile(host: &str) -> crate::model::ConnectionProfile {
    crate::model::ConnectionProfile::new("p", crate::model::Protocol::Vnc, host)
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(a, b, c, d), 5900))
}

#[test]
fn loopback_needs_no_consent_and_the_network_needs_the_exact_value() {
    let p = profile("127.0.0.1");
    assert_eq!(
        admit(&p, &[v4(127, 0, 0, 1)]),
        Ok(Destination {
            address: v4(127, 0, 0, 1),
            exposure: Exposure::Loopback,
        }),
    );

    let lan = profile("192.168.2.86");
    assert_eq!(
        admit(&lan, &[v4(192, 168, 2, 86)]),
        Err(PolicyRefusal::PlaintextNotAcknowledged {
            host: "192.168.2.86".to_string(),
        }),
        "a fresh profile must not reach a routable host in plaintext",
    );

    for value in ["", "true", "1", "acknowledged", "ACKNOWLEDGED-PLAINTEXT"] {
        let mut nearly = profile("192.168.2.86");
        nearly.extra.insert(ACK_KEY.to_string(), value.to_string());
        assert!(
            admit(&nearly, &[v4(192, 168, 2, 86)]).is_err(),
            "{value:?} is not the acknowledgement value and must not admit a plaintext connection",
        );
    }

    // Control: the exact value admits it.
    let mut acked = profile("192.168.2.86");
    acked
        .extra
        .insert(ACK_KEY.to_string(), ACK_VALUE.to_string());
    assert_eq!(
        admit(&acked, &[v4(192, 168, 2, 86)]),
        Ok(Destination {
            address: v4(192, 168, 2, 86),
            exposure: Exposure::Network,
        }),
    );
}

#[test]
fn a_mixed_resolution_is_treated_as_network_exposure() {
    let p = profile("ambiguous.local");
    let mixed = [v4(127, 0, 0, 1), v4(10, 0, 0, 5)];

    assert_eq!(
        classify(&mixed).map(|(_, e)| e),
        Some(Exposure::Network),
        "one routable answer is enough to make the destination exposed",
    );
    assert!(
        admit(&p, &mixed).is_err(),
        "…and therefore refused without an acknowledgement",
    );

    let reversed = [v4(10, 0, 0, 5), v4(127, 0, 0, 1)];
    assert_eq!(classify(&reversed).map(|(_, e)| e), Some(Exposure::Network),);

    assert_eq!(
        classify(&[v4(127, 0, 0, 1), v4(127, 0, 0, 53)]).map(|(_, e)| e),
        Some(Exposure::Loopback),
    );
}
#[test]
fn certificate_fingerprint_requires_exact_hex_pairs_and_colon_positions() {
    assert_eq!(parse_fingerprint(&"4a".repeat(32)), Some([0x4a; 32]));
    assert_eq!(parse_fingerprint(&["4A"; 32].join(":")), Some([0x4a; 32]));
    assert_eq!(parse_fingerprint(&["4A"; 32].join("-")), None);
    assert_eq!(parse_fingerprint(&"4a".repeat(31)), None);
    assert_eq!(parse_fingerprint(&"4g".repeat(32)), None);
    assert_eq!(parse_fingerprint(&"é".repeat(32)), None);
}
