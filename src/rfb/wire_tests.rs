//! The codec's refusals, each reachable from a byte literal. `transport_tests`
//! shows the worker consults them over a real socket.

use super::wire::*;

#[test]
fn server_init_bounds_its_name_length_and_its_geometry() {
    let good = server_init_bytes(1920, 1080, 15);
    assert_eq!(
        parse_server_init_prefix(&good).map(|(w, h, _, n)| (w, h, n)),
        Ok((1920, 1080, 15)),
    );

    let overlong = server_init_bytes(64, 64, 0xFFFF_FFFF);
    assert_eq!(
        parse_server_init_prefix(&overlong),
        Err(WireError::LengthTooLarge {
            field: "desktop name",
            claimed: 0xFFFF_FFFF,
        }),
    );

    for (w, h) in [(0, 1080), (1920, 0), (0, 0), (60000, 60000)] {
        assert_eq!(
            parse_server_init_prefix(&server_init_bytes(w, h, 0)),
            Err(WireError::UnusableDimensions {
                width: u32::from(w),
                height: u32::from(h),
            }),
            "a {w}x{h} desktop must be refused",
        );
    }

    assert_eq!(
        parse_server_init_prefix(&good[..10]),
        Err(WireError::Truncated {
            message: "ServerInit",
            need: SERVER_INIT_PREFIX_BYTES,
            got: 10,
        }),
    );

    // Control: 4K is admitted.
    assert!(parse_server_init_prefix(&server_init_bytes(3840, 2160, 0)).is_ok());
}

fn server_init_bytes(width: u16, height: u16, name_len: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&width.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(&CLIENT_PIXEL_FORMAT.to_bytes());
    out.extend_from_slice(&name_len.to_be_bytes());
    out
}

#[test]
fn a_rectangle_must_fit_its_framebuffer_and_use_a_requested_encoding() {
    let fit = RectangleHeader {
        x: 0,
        y: 0,
        width: 64,
        height: 64,
        encoding: ENCODING_RAW,
    };
    assert_eq!(
        plan_rectangle(fit, 64, 64),
        Ok(RectanglePlan::Raw { bytes: 64 * 64 * 4 }),
    );

    for header in [
        RectangleHeader { width: 65, ..fit },
        RectangleHeader { height: 65, ..fit },
        RectangleHeader { x: 1, ..fit },
        RectangleHeader { y: 1, ..fit },
        RectangleHeader {
            x: 65535,
            y: 65535,
            ..fit
        },
    ] {
        assert!(
            matches!(
                plan_rectangle(header, 64, 64),
                Err(WireError::RectangleOutOfBounds { .. })
            ),
            "{header:?} is not contained by a 64x64 desktop",
        );
    }

    assert!(matches!(
        plan_rectangle(RectangleHeader { width: 0, ..fit }, 64, 64),
        Err(WireError::UnusableRectangle { .. })
    ));

    // Encodings this build never requested.
    for encoding in [2, 5, 7, -239, -314] {
        assert_eq!(
            plan_rectangle(RectangleHeader { encoding, ..fit }, 64, 64),
            Err(WireError::UnsupportedEncoding { encoding }),
            "encoding {encoding} must be refused",
        );
    }

    // DesktopSize carries no pixels, so it is exempt from containment but not
    // from the ceiling.
    assert_eq!(
        plan_rectangle(
            RectangleHeader {
                width: 1280,
                height: 720,
                encoding: ENCODING_DESKTOP_SIZE,
                ..fit
            },
            64,
            64
        ),
        Ok(RectanglePlan::DesktopSize {
            width: 1280,
            height: 720
        }),
    );
    assert_eq!(
        plan_rectangle(
            RectangleHeader {
                width: 0,
                height: 0,
                encoding: ENCODING_DESKTOP_SIZE,
                ..fit
            },
            64,
            64
        ),
        Err(WireError::UnusableDimensions {
            width: 0,
            height: 0
        }),
    );
}
