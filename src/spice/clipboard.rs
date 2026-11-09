use spice_client_glib::MainChannel;
use std::sync::Arc;

use super::Control;

const CLIPBOARD: u32 = 0;
const UTF8: u32 = 1;

pub(super) fn attach(main: &MainChannel, control: &Arc<Control>) {
    let state = Arc::clone(control);
    main.connect_main_clipboard_selection_grab(move |main, selection, formats| {
        if selection == CLIPBOARD
            && formats.contains(&UTF8)
            && state.clipboard.sharing(&state.input_capture)
        {
            main.clipboard_selection_request(CLIPBOARD, UTF8);
        }
    });
    let state = Arc::clone(control);
    main.connect_main_clipboard_selection(move |_, selection, format, bytes| {
        if selection == CLIPBOARD
            && format == UTF8
            && bytes.len() <= crate::native_clipboard::LIMIT + 1
        {
            let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
            if let Ok(text) = std::str::from_utf8(bytes) {
                state.receive_clipboard(text);
            }
        }
    });
    let state = Arc::clone(control);
    main.connect_main_clipboard_selection_request(move |main, selection, format| {
        if selection != CLIPBOARD || format != UTF8 {
            return false;
        }
        if let Some(text) = state.clipboard.snapshot(&state.input_capture) {
            main.clipboard_selection_notify(CLIPBOARD, UTF8, text.as_bytes());
        } else {
            main.clipboard_selection_release(CLIPBOARD);
        }
        true
    });
}

pub(super) fn poll(main: &MainChannel, control: &Control, offered: &mut bool) {
    if !control.clipboard.sharing(&control.input_capture) {
        if std::mem::take(offered) {
            main.clipboard_selection_release(CLIPBOARD);
        }
    } else if control.clipboard.take(&control.input_capture).is_some() {
        main.clipboard_selection_grab(CLIPBOARD, &[UTF8]);
        *offered = true;
    }
}
