//! The admission boundary every profile import crosses.
//!
//! A picked file is the one input this app did not author, so what may be
//! opened, how many bytes may be read, and how much of a parsed document may
//! be retained are all bounded here rather than in each format parser. A
//! refusal is a fieldless category with compile-time banner copy; no source
//! byte and no pathname crosses this boundary.
//!
//! Blocking work runs on a bounded owner from
//! [`enzui_iced_core::blocking_task`], never on the reducer or an executor
//! task. Nothing here touches application state.

use std::path::Path;

use enzui_iced_core::blocking_task::{
    BlockingTask, BlockingTaskCancellation, BlockingTaskError, BlockingTaskOwner,
};

use crate::model::ConnectionProfile;

/// The largest source document this build will read.
///
/// A profile export of a thousand connections is tens of kilobytes; a `.rdp`
/// or Remmina file is hundreds of bytes. Half a megabyte leaves a wide margin
/// over anything this app writes while keeping the worst case a worker thread
/// can be asked to hold small enough to be uninteresting.
pub const MAX_IMPORT_BYTES: u64 = 512 * 1024;

/// The most lines a line-oriented format may carry.
pub const MAX_IMPORT_LINES: usize = 4_096;

/// The longest single line a line-oriented format may carry.
///
/// Every `.rdp` and Remmina key holds one setting. A line longer than this is
/// not a setting, so reading further cannot produce a field this build would
/// keep.
pub const MAX_IMPORT_LINE_BYTES: usize = 4_096;

/// The most profiles one export document may carry.
pub const MAX_IMPORT_PROFILES: usize = 512;

/// The most `key = value` properties one single-profile document may retain.
///
/// A Remmina profile written by Remmina itself carries on the order of sixty
/// keys, and every one of them is retained before the parser knows which it
/// can map, so this is well above that rather than beside it. Its job is the
/// hostile case: a file whose section holds thousands of keys would otherwise
/// build a vector the size of the document before any bound applied.
pub const MAX_IMPORT_ENTRIES: usize = 256;

/// The aggregate bytes one import may retain across every field it proposes.
///
/// Below [`MAX_IMPORT_BYTES`], since a decoded string is never larger than
/// its encoding and an equal ceiling could never trip. Still several times
/// the largest export this app writes, while refusing a document made of one
/// long field repeated.
pub const MAX_IMPORT_RETAINED_BYTES: usize = 256 * 1024;

/// The longest string any one imported field may retain.
///
/// Well above every display bound — `crate::display::MAX_DISPLAY_BYTES` is 64
/// and `MAX_HOST_DISPLAY_BYTES` 48 — because a stored value may legitimately
/// be longer than its elided presentation, and a foreign format's own fields
/// are bounded by neither. Far below the document ceiling, so no single field
/// can account for the whole of it.
pub const MAX_IMPORT_FIELD_BYTES: usize = 512;

/// The most port-forward rules one imported profile may retain.
pub const MAX_IMPORT_RULES: usize = 32;

/// Why an import was refused before anything was written.
///
/// Carries categories only, like [`crate::portable::JsonImportError`]: no
/// pathname, `io::Error` text or document field survives past this type, and
/// [`Self::banner_message`] is compile-time copy.
///
/// A plain open or read failure reuses the
/// [`crate::error_boundary::TransferFailure`] read classification, so one
/// table decides that copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceRefusal {
    /// The chosen name is not a regular file: a FIFO, a device, a socket or a
    /// directory. Refused on the held descriptor rather than on the pathname,
    /// so a name swapped between a check and the read cannot smuggle one in.
    NotRegularFile,
    /// The file is larger than [`MAX_IMPORT_BYTES`], either when its size was
    /// read or by the time the bytes had been.
    TooLarge,
    /// The descriptor stopped describing what it did when its length was
    /// admitted. Growth, shrink, a reported size its contents contradict, and
    /// a same-length rewrite in place all land here rather than being imported
    /// at whichever bytes arrived.
    Changed,
    /// The chosen name stopped denoting the inode that was read. Refused by
    /// comparing the held descriptor's identity against a second open of the
    /// name, so an import is never reported under a name that has come to mean
    /// something else. Nothing is published, and neither inode is touched.
    Replaced,
    /// The bytes are not valid UTF-8, so there is no text to parse
    /// ([`std::io::ErrorKind::InvalidData`] for a whole-file read).
    NotText,
    /// The file could not be opened or read at all, in the class
    /// [`crate::error_boundary::TransferFailure`] already draws for a read.
    Unreadable(crate::error_boundary::TransferFailure),
    /// The blocking import worker could not be started or has stopped, so no
    /// file was opened. Distinct from a read failure: nothing about the chosen
    /// file is known, so nothing about it is claimed.
    WorkerUnavailable,
    /// The worker is running one import and already holds the one request it
    /// will queue behind it. Nothing was opened and nothing in flight was
    /// disturbed.
    WorkerBusy,
}

impl SourceRefusal {
    /// Authored, bounded banner copy for this refusal.
    ///
    /// Contains no digit from the source, no pathname and no substring of the
    /// document, so a hostile file cannot bleed a value through the banner.
    #[must_use]
    pub fn banner_message(&self) -> String {
        match self {
            Self::NotRegularFile => "That choice is not a file this app can read. \
                 Choose a saved profile file and try again."
                .to_string(),
            Self::TooLarge => "That file is larger than this app will import. \
                 Choose a profile export and try again."
                .to_string(),
            Self::Changed => "That file changed size while it was being read. \
                 Try the import again."
                .to_string(),
            Self::Replaced => "That file was replaced while it was being read. \
                 Try the import again."
                .to_string(),
            Self::NotText => crate::error_boundary::TransferFailure::InvalidData
                .body(crate::error_boundary::TransferOperation::Read),
            Self::Unreadable(cause) => cause.body(crate::error_boundary::TransferOperation::Read),
            Self::WorkerUnavailable => "The import could not be started. \
                 Try again."
                .to_string(),
            Self::WorkerBusy => "Another import is still finishing. Wait for \
                 it to report, then try again."
                .to_string(),
        }
    }
}

/// Read a chosen file as text, or refuse it.
///
/// Opens with [`enzui_iced_core::atomic_state::open_state_file_nofollow`]:
/// the name is resolved once, a terminal symlink is refused by the kernel,
/// and a planted FIFO returns from the open instead of blocking. The
/// descriptor's type is then validated, refusing FIFOs, devices, sockets and
/// directories.
///
/// The containing directory need only be a directory, because connection
/// files legitimately arrive from shared or group-writable folders. Every
/// decision reads the opened descriptor, never the pathname.
///
/// After the bounded read, any of these refuses the import:
///
/// * the descriptor delivered a different length than it admitted;
/// * the descriptor's metadata changed during the read (a same-length
///   in-place rewrite);
/// * the name no longer denotes the inode that was read.
///
/// The last check opens a second time only to compare identity; the bytes in
/// hand are never re-read and no inode is written or removed.
///
/// These checks detect change; they cannot prove stability. A rewrite within
/// one timestamp tick is published, but a noticed change never is.
pub fn read_text(path: &Path) -> Result<String, SourceRefusal> {
    use std::io::Read;

    let file = open_regular(path)?;
    let admitted = described(&file)?;
    if admitted.0 > MAX_IMPORT_BYTES {
        return Err(SourceRefusal::TooLarge);
    }

    #[cfg(test)]
    hooks::after_admit(path);

    // No `with_capacity`: the admitted length is the file's claim about itself,
    // and reserving on it lets a lying size decide one allocation.
    let mut bytes = Vec::new();
    let read = (&file)
        .take(MAX_IMPORT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|err| SourceRefusal::Unreadable(classify(&err)))? as u64;
    if read > MAX_IMPORT_BYTES {
        return Err(SourceRefusal::TooLarge);
    }
    if read != admitted.0 || described(&file)? != admitted {
        return Err(SourceRefusal::Changed);
    }

    #[cfg(test)]
    hooks::after_read(path);

    // A vanished name or a non-regular file has stopped denoting the read inode
    // just as surely as a different inode; all are the same refusal, not a read
    // failure.
    let held = identity(&file)?;
    let current = open_regular(path).ok().and_then(|f| identity(&f).ok());
    if current != Some(held) {
        return Err(SourceRefusal::Replaced);
    }

    String::from_utf8(bytes).map_err(|_| SourceRefusal::NotText)
}

/// Open `path` as a regular file through the framework's reading primitive.
fn open_regular(path: &Path) -> Result<std::fs::File, SourceRefusal> {
    enzui_iced_core::atomic_state::open_state_file_nofollow(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::InvalidInput {
            // The primitive's own `fstat` refusal of a non-regular descriptor.
            SourceRefusal::NotRegularFile
        } else {
            // Includes a no-follow symlink refusal: naming it would need an app-local
            // errno table, since the matching `io::ErrorKind` is not stable.
            SourceRefusal::Unreadable(classify(&err))
        }
    })
}

/// What one descriptor says about itself: its length, and when it last
/// changed.
///
/// The timestamp catches a same-length rewrite into the same inode. Where a
/// filesystem reports none, both sides are `None` and the comparison falls
/// back to length alone: a narrowing, never a false refusal.
fn described(file: &std::fs::File) -> Result<(u64, Option<std::time::SystemTime>), SourceRefusal> {
    let meta = file
        .metadata()
        .map_err(|err| SourceRefusal::Unreadable(classify(&err)))?;
    Ok((meta.len(), meta.modified().ok()))
}

/// The `(device, inode)` one descriptor refers to.
///
/// From `fstat` through `std`'s own Unix metadata, so no platform table is
/// duplicated here.
fn identity(file: &std::fs::File) -> Result<(u64, u64), SourceRefusal> {
    use std::os::unix::fs::MetadataExt;

    let meta = file
        .metadata()
        .map_err(|err| SourceRefusal::Unreadable(classify(&err)))?;
    Ok((meta.dev(), meta.ino()))
}

/// The read-side class of one `io::Error`, discarding the error itself.
fn classify(err: &std::io::Error) -> crate::error_boundary::TransferFailure {
    crate::error_boundary::TransferFailure::classify_read(err)
}

/// Deterministic seams inside [`read_text`], at the two points its race
/// refusals defend.
///
/// Growth, shrink and replacement are races against a read in progress;
/// arranging them by timing would pass on a quiet machine whatever the code
/// does.
///
/// Process-global because [`read_text`] runs on the import worker. Tests that
/// install a seam hold [`guard`] for their duration.
#[cfg(test)]
pub(crate) mod hooks {
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};

    type Hook = Box<dyn Fn(&Path) + Send>;

    struct Seams {
        after_admit: Option<Hook>,
        after_read: Option<Hook>,
    }

    fn seams() -> &'static Mutex<Seams> {
        static SEAMS: OnceLock<Mutex<Seams>> = OnceLock::new();
        SEAMS.get_or_init(|| {
            Mutex::new(Seams {
                after_admit: None,
                after_read: None,
            })
        })
    }

    pub(super) fn after_admit(path: &Path) {
        let hook = seams().lock().ok().and_then(|mut s| s.after_admit.take());
        if let Some(f) = hook {
            f(path);
            if let Ok(mut s) = seams().lock() {
                s.after_admit = Some(f);
            }
        }
    }

    pub(super) fn after_read(path: &Path) {
        let hook = seams().lock().ok().and_then(|mut s| s.after_read.take());
        if let Some(f) = hook {
            f(path);
            if let Ok(mut s) = seams().lock() {
                s.after_read = Some(f);
            }
        }
    }
}

/// Whether a line-oriented document is within the line bounds.
///
/// Counts with an early stop, so a document past the bound is refused without
/// its remaining lines being walked.
#[must_use]
pub fn lines_within_bounds(text: &str) -> bool {
    let mut seen = 0usize;
    for line in text.lines() {
        seen += 1;
        if seen > MAX_IMPORT_LINES || line.len() > MAX_IMPORT_LINE_BYTES {
            return false;
        }
    }
    true
}

/// The retention budget one parse may spend, cleared on entry and on drop.
///
/// Leftover state would make the next import refuse a fitting document, or
/// misreport the reason for refusing one.
///
/// One counter per thread is one counter per import: the import worker is
/// single and serial, and `libtest` runs each parser test on its own thread.
pub struct RetainedBudget(());

impl RetainedBudget {
    /// Reserve the budget for one parse on this thread.
    #[must_use]
    pub fn open() -> Self {
        RETAINED.with(|c| c.set(0));
        OVERFLOWED.with(|c| c.set(None));
        Self(())
    }
}

impl Drop for RetainedBudget {
    fn drop(&mut self) {
        RETAINED.with(|c| c.set(0));
        OVERFLOWED.with(|c| c.set(None));
    }
}

thread_local! {
    /// Bytes charged against [`MAX_IMPORT_RETAINED_BYTES`] by this parse.
    static RETAINED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Which bound, if any, rather than the document's shape ended this parse.
    static OVERFLOWED: std::cell::Cell<Option<RetentionBound>> =
        const { std::cell::Cell::new(None) };
}

/// Which retention ceiling refused a document.
///
/// Two, because the guidance differs. A library of too many connections can be
/// split and imported in parts; a document whose individual settings are
/// larger than this app retains cannot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionBound {
    /// More list elements than the list's cap: profiles, or one profile's
    /// forward rules.
    Count,
    /// One field longer than [`MAX_IMPORT_FIELD_BYTES`], or an aggregate past
    /// [`MAX_IMPORT_RETAINED_BYTES`].
    Fields,
}

/// Whether this build will retain `value` as one field, charging it if so.
///
/// Answered before the value is copied out of the parser's buffer, so an
/// over-budget field is never allocated.
///
/// [`MAX_IMPORT_FIELD_BYTES`] refuses one long field in a short file;
/// [`MAX_IMPORT_RETAINED_BYTES`] refuses many reasonable fields whose total
/// is too large.
#[must_use]
pub fn admit_field(value: &str) -> bool {
    if value.len() > MAX_IMPORT_FIELD_BYTES {
        note_overflow(RetentionBound::Fields);
        return false;
    }
    charge(value.len())
}

/// Charge `bytes` against the aggregate ceiling, or refuse.
#[must_use]
fn charge(bytes: usize) -> bool {
    RETAINED.with(|c| {
        let next = c.get().saturating_add(bytes);
        if next > MAX_IMPORT_RETAINED_BYTES {
            note_overflow(RetentionBound::Fields);
            return false;
        }
        c.set(next);
        true
    })
}

/// Record that `bound`, and not the document's shape, ended the parse in
/// progress.
///
/// A `serde` refusal is opaque, and its `Display` echoes document content, so
/// the cause is carried out of band.
///
/// First writer wins: the outermost refusal ended the parse, and a later
/// charge would relabel it.
pub fn note_overflow(bound: RetentionBound) {
    OVERFLOWED.with(|c| {
        if c.get().is_none() {
            c.set(Some(bound));
        }
    });
}

/// Which retention bound ended the parse in progress, if one did.
#[must_use]
pub fn overflowed() -> Option<RetentionBound> {
    OVERFLOWED.with(std::cell::Cell::get)
}

/// Deserialize one string, admitting it against the retention bounds first.
///
/// # Errors
/// The deserializer's own error when the value is not a string, and a bounded
/// refusal when it is one this import will not retain.
pub fn bounded_string<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Bounded;

    impl serde::de::Visitor<'_> for Bounded {
        type Value = String;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "a string this import will retain")
        }

        fn visit_str<E>(self, v: &str) -> Result<String, E>
        where
            E: serde::de::Error,
        {
            if admit_field(v) {
                Ok(v.to_owned())
            } else {
                Err(E::custom("field exceeds an import retention bound"))
            }
        }

        fn visit_string<E>(self, v: String) -> Result<String, E>
        where
            E: serde::de::Error,
        {
            // An owned string arrives only when the source had escapes and the
            // parser already built one in its scratch space. Admitting it here
            // still decides before this import retains it.
            if admit_field(&v) {
                Ok(v)
            } else {
                Err(E::custom("field exceeds an import retention bound"))
            }
        }
    }

    d.deserialize_string(Bounded)
}

/// Deserialize an optional string through [`bounded_string`].
///
/// # Errors
/// As [`bounded_string`], plus the deserializer's own error when the value is
/// neither a string nor absent.
pub fn bounded_option_string<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Maybe;

    impl<'de> serde::de::Visitor<'de> for Maybe {
        type Value = Option<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "an optional string this import will retain")
        }

        fn visit_none<E>(self) -> Result<Option<String>, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Option<String>, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, d: D) -> Result<Option<String>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            bounded_string(d).map(Some)
        }
    }

    d.deserialize_option(Maybe)
}

/// Deserialize a sequence of at most `cap` elements.
///
/// The element past the cap is skipped rather than deserialized, and no
/// length is reserved on the document's say-so.
///
/// # Errors
/// The deserializer's own error for a malformed element, and a bounded refusal
/// when the sequence is longer than `cap`.
pub fn capped_seq<'de, D, T>(d: D, cap: usize, bound: RetentionBound) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct Capped<T> {
        cap: usize,
        bound: RetentionBound,
        item: std::marker::PhantomData<T>,
    }

    impl<'de, T> serde::de::Visitor<'de> for Capped<T>
    where
        T: serde::Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {} items", self.cap)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<T>, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            use serde::de::Error as _;

            // `size_hint` is the document's claim about itself and is not used
            // to reserve.
            let mut out: Vec<T> = Vec::new();
            while out.len() < self.cap {
                match seq.next_element()? {
                    Some(item) => out.push(item),
                    None => return Ok(out),
                }
            }
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                note_overflow(self.bound);
                return Err(A::Error::custom("sequence exceeds an import bound"));
            }
            Ok(out)
        }
    }

    d.deserialize_seq(Capped {
        cap,
        bound,
        item: std::marker::PhantomData,
    })
}

/// Which parser a chosen file is handed to.
///
/// Derived from a [`crate::picker::TransferTarget`] by
/// [`crate::picker::TransferTarget::import_format`], so an export target
/// cannot reach [`load`] at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportFormat {
    /// A Microsoft `.rdp` settings file: one profile.
    Rdp,
    /// A Remmina INI profile: one profile, with unmapped source fields
    /// reported.
    Remmina,
    /// This app's own export document: many profiles.
    Document,
}

/// What a dispatched import produced, before anything was written.
///
/// Every variant is a proposal. Nothing in the store or the model has changed
/// when one of these reaches the reducer, which is what lets a stale answer be
/// dropped by doing nothing at all.
#[derive(Clone, Debug)]
pub enum ImportOutcome {
    /// An export document's profiles, in document order.
    Document(Vec<ConnectionProfile>),
    /// One profile from a single-row format.
    Single(ConnectionProfile),
    /// One profile whose source carried fields this build could not map.
    Reported {
        profile: ConnectionProfile,
        unsupported: Vec<String>,
        has_reported_password: bool,
        omitted: usize,
    },
    /// A refusal, as authored banner copy.
    ///
    /// The only producers are the `banner_message` methods of
    /// [`SourceRefusal`] and the three parser error enums, all of which are
    /// fieldless. No pathname and no byte of the document reaches this string.
    Refused(String),
}

/// How many imports run at once.
///
/// One. The read, the parse and the retention charge are one decision about a
/// single document, and a second concurrent parse would double the worst-case
/// retention the ceilings were calibrated against.
const IMPORT_WORKERS: std::num::NonZeroUsize = std::num::NonZeroUsize::new(1).unwrap();

/// How many requests the owner will hold beyond the one it is running.
///
/// One. Repeated clicks, and repeated cancel-and-retry, would otherwise leave
/// a path queued for every one of them behind a read that has not finished — a
/// collection whose size the user sets and nothing bounds. With a single slot
/// the newest request supersedes the owned one and anything past that is told
/// so.
const IMPORT_QUEUE_DEPTH: std::num::NonZeroUsize = std::num::NonZeroUsize::new(1).unwrap();

/// The bounded owner every import's open, read and parse runs on.
///
/// The framework owner settles saturation, cancellation, shutdown and a
/// panicking worker as terminal answers. A dedicated thread, not an executor
/// task, so a slow read never costs a drawn frame.
///
/// `None` when the thread could not be started. The `OnceLock` keeps
/// whatever it is first given, so caching
/// [`BlockingTaskOwner::unavailable`] would turn one transient spawn failure
/// into permanent refusals; leaving it empty lets the next press retry.
fn owner() -> Option<&'static BlockingTaskOwner> {
    static OWNER: std::sync::OnceLock<BlockingTaskOwner> = std::sync::OnceLock::new();

    if let Some(started) = OWNER.get() {
        return Some(started);
    }
    let started =
        BlockingTaskOwner::new("remote-import", IMPORT_WORKERS, IMPORT_QUEUE_DEPTH).ok()?;
    // Losing this race means another caller started one first. The loser is
    // dropped here, which shuts down and joins threads that have taken no
    // work, and the winner is what every caller goes on to use.
    let _ = OWNER.set(started);
    OWNER.get()
}

/// A claimed import's answer.
///
/// Two shapes because a claim can already be complete: a one-worker owner may
/// finish a very small document between the submission and the first look at
/// it, and an answer that has arrived is not a refusal.
pub enum PendingImport {
    /// Accepted and still running or queued.
    Running(BlockingTask<ImportOutcome>),
    /// Already answered at claim time.
    Settled(Box<ImportOutcome>),
}

impl PendingImport {
    /// Wait for the owner's answer, and nothing else, so the task a reducer
    /// holds performs none of the blocking work itself.
    ///
    /// Every terminal refusal the owner can produce reads as the import not
    /// having been startable. A cancelled generation reaches here too, and its
    /// answer is dropped by the reducer's generation check rather than
    /// rendered.
    pub async fn settle(self) -> ImportOutcome {
        match self {
            Self::Settled(outcome) => *outcome,
            Self::Running(task) => task.await.into_result().unwrap_or_else(|_| {
                ImportOutcome::Refused(SourceRefusal::WorkerUnavailable.banner_message())
            }),
        }
    }
}

/// One claimed import: its answer, and the handle that abandons it.
pub struct ImportClaim {
    /// Where the answer will arrive.
    pub pending: PendingImport,
    /// Retained by the reducer for as long as this import is the owned one.
    pub cancellation: BlockingTaskCancellation<ImportOutcome>,
}

// The bounded owner and fault hooks are process-wide; concurrent tests would
// consume each other's slots or trigger each other's hooks.

/// Claim the owner's free slot for `path`, or refuse without waiting.
///
/// Every outcome is immediate because the caller is the reducer; the owner's
/// saturation answer is already terminal, so one poll decides it.
///
/// A request the reducer stopped owning holds its slot until its job retires,
/// because a read in progress cannot be interrupted. Cancellation frees
/// attention, not capacity.
///
/// # Errors
/// [`SourceRefusal::WorkerBusy`] when the slot is taken, and
/// [`SourceRefusal::WorkerUnavailable`] when the owner could not be started,
/// is shut down, or had a worker end by unwinding.
pub fn enqueue(
    generation: u64,
    format: ImportFormat,
    path: std::path::PathBuf,
) -> Result<ImportClaim, SourceRefusal> {
    use iced::futures::FutureExt;

    let owner = owner().ok_or(SourceRefusal::WorkerUnavailable)?;
    let mut task = owner.submit(generation, move |context| {
        if context.is_cancelled() {
            // Nothing is opened for a request that was abandoned before it
            // started. The owner has already published this generation's
            // terminal answer, so what is returned here is discarded.
            return ImportOutcome::Refused(SourceRefusal::WorkerUnavailable.banner_message());
        }
        load(format, &path)
    });
    let cancellation = task.cancellation();
    // Polled through a borrow, so an accepted claim is not dropped — and
    // dropping a live task is itself a cancellation.
    match (&mut task).now_or_never() {
        None => Ok(ImportClaim {
            pending: PendingImport::Running(task),
            cancellation,
        }),
        Some(settlement) => match settlement.into_result() {
            Ok(outcome) => Ok(ImportClaim {
                pending: PendingImport::Settled(Box::new(outcome)),
                cancellation,
            }),
            Err(BlockingTaskError::Busy) => Err(SourceRefusal::WorkerBusy),
            Err(_) => Err(SourceRefusal::WorkerUnavailable),
        },
    }
}

/// Read and parse one chosen file, blocking the calling thread.
///
/// The body the owner's worker runs for an [`enqueue`]d claim. It takes no
/// application state and returns a proposal, so the reducer's only job on the
/// answer is to decide whether it is still wanted. Credentials are excluded here rather than downstream — a
/// parser that grew a password field would have to be changed here to publish
/// it.
#[must_use]
pub fn load(format: ImportFormat, path: &Path) -> ImportOutcome {
    let text = match read_text(path) {
        Ok(text) => text,
        Err(refusal) => return ImportOutcome::Refused(refusal.banner_message()),
    };
    match format {
        ImportFormat::Document => match crate::portable::import_json(&text) {
            Err(e) => ImportOutcome::Refused(e.banner_message()),
            Ok(profiles) => ImportOutcome::Document(profiles),
        },
        ImportFormat::Rdp => {
            // The file stem names a profile that would otherwise have none. It is not a
            // claim the document made, so an overlong one is elided rather than refused.
            let fallback = crate::display::bound_display_name(
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("Imported"),
            );
            match crate::portable::import_rdp(&text, &fallback) {
                Err(e) => ImportOutcome::Refused(e.banner_message()),
                Ok(profile) => ImportOutcome::Single(profile),
            }
        }
        ImportFormat::Remmina => match crate::import_remmina::parse_remmina(&text) {
            Err(e) => ImportOutcome::Refused(e.banner_message()),
            Ok(mut imported) => {
                // The parser already leaves this false; set it again at the
                // boundary so a future reshuffle upstream cannot let an
                // imported profile claim a password this keyring never held.
                imported.profile.has_keyring_password = false;
                ImportOutcome::Reported {
                    profile: imported.profile,
                    unsupported: imported.unsupported,
                    has_reported_password: imported.has_reported_password,
                    omitted: imported.omitted_warnings,
                }
            }
        },
    }
}
