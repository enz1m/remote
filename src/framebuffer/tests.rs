//! Frame policy: admission ceilings, retention bounds, generation and ordering
//! refusal, and display-to-remote pointer mapping.

use super::*;
use enzui_iced_core::frame_plan::FrameSeq;
use enzui_iced_core::media::{BoundedFrameSink, Generation};

fn bytes(width: u32, height: u32) -> FrameBytes {
    FrameBytes::new(vec![0x7F; width as usize * height as usize * 4])
}

#[test]
fn a_framebuffer_past_any_ceiling_is_refused_and_a_real_desktop_is_not() {
    let seq = FrameSeq(0);
    let generation = Generation::FIRST;

    assert!(matches!(
        admit(generation, seq, 0, 1080, FrameBytes::new(Vec::new())),
        Err(FrameRefusal::OverLimit(DecodeVerdict::ZeroDimension { .. })),
    ));

    // The other edge is small enough that the area and byte ceilings are not what
    // refuses it.
    assert!(
        matches!(
            admit(generation, seq, 8193, 4, FrameBytes::new(Vec::new())),
            Err(FrameRefusal::OverLimit(DecodeVerdict::WidthTooLarge { .. })),
        ),
        "the width ceiling must be the one that refuses an over-wide frame",
    );
    assert!(
        matches!(
            admit(generation, seq, 4, 8193, FrameBytes::new(Vec::new())),
            Err(FrameRefusal::OverLimit(
                DecodeVerdict::HeightTooLarge { .. }
            )),
        ),
        "…and the height ceiling an over-tall one",
    );

    assert!(
        matches!(
            admit(generation, seq, 8192, 8192, FrameBytes::new(Vec::new())),
            Err(FrameRefusal::OverLimit(DecodeVerdict::TooManyPixels { .. })),
        ),
        "two legal edges can still multiply past the area ceiling",
    );

    // Control: a 4K desktop is admitted. Every refused case above passed an empty
    // buffer and was rejected on geometry alone.
    let frame = admit(generation, seq, 3840, 2160, bytes(3840, 2160))
        .expect("a 3840x2160 desktop is the size this build is scaled for");
    assert_eq!((frame.width(), frame.height()), (3840, 2160));
    assert_eq!(
        frame.byte_len(),
        3840 * 2160 * 4,
        "the admitted frame keeps its own buffer, untouched",
    );
}

#[test]
fn a_buffer_that_disagrees_with_its_geometry_is_refused() {
    let short = admit(Generation::FIRST, FrameSeq(0), 64, 64, bytes(64, 1));
    assert!(
        matches!(
            short,
            Err(FrameRefusal::Malformed(
                enzui_iced_core::media::FrameFormatError::BufferSizeMismatch { .. }
            )),
        ),
        "a short buffer must be refused, got {short:?}",
    );

    let long = admit(Generation::FIRST, FrameSeq(0), 64, 64, bytes(64, 128));
    assert!(
        matches!(long, Err(FrameRefusal::Malformed(_))),
        "an over-long buffer is equally a disagreement, got {long:?}",
    );

    // Control: the exact length is admitted.
    assert!(admit(Generation::FIRST, FrameSeq(0), 64, 64, bytes(64, 64)).is_ok());
}

#[test]
fn frames_arriving_faster_than_they_are_consumed_stay_bounded() {
    let mut sink = BoundedFrameSink::new(Generation::FIRST);
    for n in 0..20u64 {
        let frame = admit(Generation::FIRST, FrameSeq(n), 320, 200, bytes(320, 200))
            .expect("each frame is well-formed");
        sink.deliver(frame);
    }

    assert!(
        sink.retained_buffers() <= 3,
        "at most one displayed, one in flight and one queued may be retained; \
         got {}",
        sink.retained_buffers(),
    );
    assert!(
        sink.dropped_for_bound() > 0,
        "eighteen of the twenty had to be displaced; if none were, the sink \
         is accumulating them somewhere",
    );
    assert!(
        sink.retained_bytes() <= MAX_RETAINED_BYTES,
        "retention must stay under the documented ceiling; got {} bytes",
        sink.retained_bytes(),
    );

    // Coalescing keeps the latest frame, not the first.
    sink.present();
    assert_eq!(
        sink.displayed().map(|f| f.seq()),
        Some(FrameSeq(0)),
        "the first delivery went straight to in-flight and is presented first",
    );
    sink.present();
    assert_eq!(
        sink.displayed().map(|f| f.seq()),
        Some(FrameSeq(19)),
        "…and the queue holds the newest, never an older one it displaced",
    );
}

#[test]
fn a_stale_or_out_of_order_frame_is_discarded() {
    use enzui_iced_core::media::Delivery;

    let current = Generation::FIRST.next();
    let mut sink = BoundedFrameSink::new(current);

    let accepted =
        sink.deliver(admit(current, FrameSeq(5), 32, 32, bytes(32, 32)).expect("well-formed"));
    assert!(matches!(accepted, Delivery::Retained));

    let stale = sink.deliver(
        admit(Generation::FIRST, FrameSeq(9), 32, 32, bytes(32, 32)).expect("well-formed"),
    );
    assert!(
        matches!(stale, Delivery::DiscardedStale { .. }),
        "a frame from the previous source must be dropped however new its \
         sequence is; got {stale:?}",
    );

    let backwards =
        sink.deliver(admit(current, FrameSeq(4), 32, 32, bytes(32, 32)).expect("well-formed"));
    assert!(
        matches!(backwards, Delivery::DiscardedOutOfOrder { .. }),
        "a frame older than one already retained must be dropped; got \
         {backwards:?}",
    );

    assert_eq!(sink.discarded_stale(), 1);
    assert_eq!(sink.discarded_out_of_order(), 1);
    assert_eq!(
        sink.retained_buffers(),
        1,
        "neither refused buffer may be retained",
    );

    // Control: a newer sequence in the current generation is still accepted.
    let newer =
        sink.deliver(admit(current, FrameSeq(6), 32, 32, bytes(32, 32)).expect("well-formed"));
    assert!(matches!(newer, Delivery::Retained), "got {newer:?}");
}

#[test]
fn a_pointer_maps_to_the_pixel_under_it_and_the_letterbox_maps_to_nothing() {
    // 400x200 in 400x400 under Contain: scale 1, drawn from y = 100 to 300.
    let slot = Size::new(400.0, 400.0);
    let frame = (400u32, 200u32);

    assert_eq!(
        remote_pixel(slot, frame, ScalingMode::ScaleToFit, Point::new(0.5, 100.5)),
        Some((0, 0)),
        "the picture's top-left corner is the remote's origin",
    );
    assert_eq!(
        remote_pixel(
            slot,
            frame,
            ScalingMode::ScaleToFit,
            Point::new(399.5, 299.5)
        ),
        Some((399, 199)),
        "…and its bottom-right corner is the remote's last pixel",
    );
    assert_eq!(
        remote_pixel(
            slot,
            frame,
            ScalingMode::ScaleToFit,
            Point::new(200.0, 50.0)
        ),
        None,
        "the bar above the picture is not the remote",
    );
    assert_eq!(
        remote_pixel(
            slot,
            frame,
            ScalingMode::ScaleToFit,
            Point::new(200.0, 350.0)
        ),
        None,
        "…nor the bar below it",
    );
}
