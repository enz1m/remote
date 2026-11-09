use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use ironrdp_cliprdr::{CliprdrClient, backend::CliprdrBackend, pdu::*};
use ironrdp_core::impl_as_any;
use ironrdp_session::ActiveStage;

use super::Control;

pub(super) fn poll(stage: &mut ActiveStage) -> anyhow::Result<Vec<u8>> {
    let context = stage
        .get_svc_processor::<CliprdrClient>()
        .and_then(|channel| channel.downcast_backend::<Backend>())
        .map(|backend| backend.context.clone());
    match context {
        Some(context) => context.poll(stage),
        None => Ok(Vec::new()),
    }
}

#[derive(Debug)]
enum Request {
    Advertise,
    Paste,
    Data(ClipboardFormatId),
}

#[derive(Clone, Debug)]
pub(super) struct Context {
    control: Arc<Control>,
    requests: Arc<Mutex<VecDeque<Request>>>,
}

impl Context {
    pub(super) fn new(control: &Arc<Control>) -> Self {
        Self {
            control: Arc::clone(control),
            requests: Arc::default(),
        }
    }
    pub(super) fn channel(&self) -> CliprdrClient {
        CliprdrClient::new(Box::new(Backend {
            context: self.clone(),
            pending: false,
            obsolete: false,
            remote_text: false,
        }))
    }
    fn enqueue(&self, request: Request) {
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if requests.len() >= 16 {
            self.control.fail_input();
        } else {
            requests.push_back(request);
        }
    }
    pub(super) fn poll(&self, stage: &mut ActiveStage) -> anyhow::Result<Vec<u8>> {
        if self
            .control
            .clipboard
            .take(&self.control.input_capture)
            .is_some()
        {
            self.enqueue(Request::Advertise);
        }
        let requests: Vec<_> = self
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect();
        let mut output = Vec::new();
        for request in requests {
            let Some(channel) = stage.get_svc_processor_mut::<CliprdrClient>() else {
                break;
            };
            let messages = match request {
                Request::Advertise => channel.initiate_copy(&if self
                    .control
                    .clipboard
                    .snapshot(&self.control.input_capture)
                    .is_some()
                {
                    vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]
                } else {
                    Vec::new()
                })?,
                Request::Paste if self.control.clipboard.sharing(&self.control.input_capture) => {
                    channel.initiate_paste(ClipboardFormatId::CF_UNICODETEXT)?
                }
                Request::Paste => {
                    if let Some(backend) = channel.downcast_backend_mut::<Backend>() {
                        backend.pending = false;
                        backend.obsolete = false;
                    }
                    continue;
                }
                Request::Data(format) => {
                    let text = self.control.clipboard.snapshot(&self.control.input_capture);
                    let response = if format == ClipboardFormatId::CF_UNICODETEXT {
                        text.map(|s| {
                            FormatDataResponse::new_unicode_string(&s.replace('\n', "\r\n"))
                        })
                    } else {
                        None
                    }
                    .unwrap_or_else(FormatDataResponse::new_error);
                    channel.submit_format_data(response)?
                }
            };
            output.extend(stage.process_svc_processor_messages(messages)?);
        }
        Ok(output)
    }
}

#[derive(Debug)]
struct Backend {
    context: Context,
    pending: bool,
    obsolete: bool,
    remote_text: bool,
}
impl_as_any!(Backend);
impl Backend {
    fn request_text(&mut self) {
        if self.remote_text
            && self
                .context
                .control
                .clipboard
                .sharing(&self.context.control.input_capture)
        {
            self.pending = true;
            self.context.enqueue(Request::Paste);
        }
    }
}
impl CliprdrBackend for Backend {
    fn temporary_directory(&self) -> &str {
        ""
    }
    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }
    fn on_ready(&mut self) {
        self.context.control.clipboard.set_available(true);
    }
    fn on_request_format_list(&mut self) {
        self.context.enqueue(Request::Advertise);
    }
    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}
    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        self.remote_text = formats
            .iter()
            .any(|f| f.id == ClipboardFormatId::CF_UNICODETEXT);
        if self.pending {
            self.obsolete = true;
        } else {
            self.request_text();
        }
    }
    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        self.context.enqueue(Request::Data(request.format));
    }
    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if !self.pending {
            return;
        }
        self.pending = false;
        if std::mem::take(&mut self.obsolete) {
            self.request_text();
            return;
        }
        if !response.is_error()
            && let Some(text) = decode(response.data())
        {
            self.context.control.receive_clipboard(&text);
        }
    }
    fn on_file_contents_request(&mut self, _: FileContentsRequest) {}
    fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}
    fn on_lock(&mut self, _: LockDataId) {}
    fn on_unlock(&mut self, _: LockDataId) {}
}

fn decode(data: &[u8]) -> Option<String> {
    if data.len() < 2
        || data.len() > crate::native_clipboard::LIMIT * 2 + 2
        || !data.len().is_multiple_of(2)
        || !data.ends_with(&[0, 0])
    {
        return None;
    }
    let words: Vec<_> = data[..data.len() - 2]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .collect();
    let text = String::from_utf16(&words).ok()?;
    crate::native_clipboard::normalize(&text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_new_copy_invalidates_the_in_flight_reply_and_capture_revocation_blocks_delivery() {
        use iced::futures::FutureExt;
        use std::sync::atomic::{AtomicBool, AtomicU64};
        let (events, mut stream) = crate::protocol::SessionStream::channel();
        let control = Arc::new(Control {
            route: std::sync::Mutex::new(None),
            cancelled: AtomicBool::new(false),
            input_failed: AtomicBool::new(false),
            active: AtomicBool::new(true),
            input_capture: Arc::new(AtomicBool::new(true)),
            clipboard: crate::native_clipboard::Clipboard::new(true),
            requested_size: AtomicU64::new(0),
            dynamic_resize: std::sync::atomic::AtomicBool::new(false),
            resize_available: std::sync::atomic::AtomicBool::new(false),
            socket: Mutex::new(None),
            events,
        });
        control.clipboard.set_available(true);
        let mut backend = Backend {
            context: Context::new(&control),
            pending: true,
            obsolete: false,
            remote_text: true,
        };
        backend.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
        backend.on_format_data_response(FormatDataResponse::new_unicode_string("obsolete"));
        assert!(stream.recv().now_or_never().is_none());
        assert!(backend.pending);
        backend.on_format_data_response(FormatDataResponse::new_unicode_string("current"));
        let event = stream.recv().now_or_never().flatten().unwrap();
        assert!(
            matches!(event, crate::state_machine::SessionEvent::Clipboard(text) if text.0.as_str() == "current")
        );
        backend.pending = true;
        control
            .input_capture
            .store(false, std::sync::atomic::Ordering::SeqCst);
        backend.on_format_data_response(FormatDataResponse::new_unicode_string("released"));
        assert!(stream.recv().now_or_never().is_none());
    }

    #[test]
    fn unicode_text_rejects_malformed_oversized_and_embedded_null_data() {
        assert_eq!(
            decode(FormatDataResponse::new_unicode_string("café\r\n雪").data()).as_deref(),
            Some("café\n雪")
        );
        for bytes in [
            vec![1],
            vec![0x00, 0xd8, 0, 0],
            vec![97, 0, 0, 0, 98, 0, 0, 0],
            vec![0; crate::native_clipboard::LIMIT * 2 + 4],
        ] {
            assert!(decode(&bytes).is_none());
        }
    }
}
