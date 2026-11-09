//! Import a Remmina connection profile (`.remmina`, INI-shaped) as a
//! [`ConnectionProfile`], reporting every field that was not translated.
//!
//! # Contract
//!
//! The parser is pure: it takes an `&str` and returns [`ImportedRemmina`],
//! carrying the profile, a bounded ordered window of untranslated source
//! fields, and the count that did not fit in that window.
//!
//! No field is dropped silently. Every unrecognised key, and every recognised
//! key that cannot be translated faithfully (a malformed number, a
//! one-axis resolution, an encrypted `password=`), appears in
//! [`ImportedRemmina::unsupported`] or is counted in
//! [`ImportedRemmina::omitted_warnings`], and the result screen reports both.
//!
//! # Passwords are not imported
//!
//! Remmina's AES-encrypted `password=` is not decrypted, and imports never
//! write the credential store: doing so could raise an unlock prompt and
//! transfer a secret the review UI never showed. The field is reported so
//! the user knows to retype it; see
//! [`ImportedRemmina::has_reported_password`].

use crate::display::{MAX_WARNING_ENTRIES, bound_warning_line};
use crate::model::{ConnectionProfile, Protocol};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// A successfully-parsed Remmina profile, plus the source fields that were
/// present but not translated (see the module docs for the contract).
#[derive(Clone, Debug)]
pub struct ImportedRemmina {
    /// The translated profile. `has_keyring_password` is always `false`; imports
    /// never touch the credential store.
    pub profile: ConnectionProfile,
    /// Untranslated source fields as bounded `key = value` lines, in file order,
    /// capped at [`crate::display::MAX_WARNING_ENTRIES`]; fields beyond the cap
    /// are counted in [`Self::omitted_warnings`].
    pub unsupported: Vec<String>,
    /// Unsupported source fields that did not fit in [`Self::unsupported`].
    /// A non-zero value is announced on the banner via
    /// [`crate::display::bounded_warning_summary`].
    pub omitted_warnings: usize,
    /// `true` when the source carried a non-empty `password=` key. The password
    /// is neither decrypted nor stored; this drives the result screen's
    /// "retype one field" line.
    pub has_reported_password: bool,
}

/// The reasons [`parse_remmina`] refuses an input outright.
///
/// Refusing, rather than returning an empty profile, keeps a caller from
/// persisting a nameless VNC row with an empty host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemminaParseError {
    /// The file did not have a `[remmina]` section, or was empty.
    NoConnectionSection,
    /// The `server=` key was missing or empty; a usable Remmina profile always
    /// names its host.
    NoServer,
    /// The file has more lines, or a longer line, than a settings file has.
    /// Refused before any entry is collected, so no part of it is retained.
    TooComplex,
}

impl RemminaParseError {
    /// A one-sentence copy for the import banner.
    pub fn banner_message(&self) -> String {
        match self {
            Self::NoConnectionSection => {
                "This does not look like a Remmina profile: no [remmina] section.".into()
            }
            Self::NoServer => {
                "The Remmina profile has no `server=` line, so there is no host to save.".into()
            }
            Self::TooComplex => {
                "This Remmina profile holds more settings than this app will read. \
                 Choose a different file and try again."
                    .into()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

/// The Remmina keys this importer knows how to translate. Anything outside
/// this set is reported as unsupported — explicit rather than a
/// case-by-case guess.
///
/// Kept exhaustive because a *missing* case in a match here is caught by
/// the tests below (`every_translated_key_is_covered_by_the_translator`),
/// but a missing case in a `HashMap` lookup would silently drop the field.
#[cfg(test)]
const TRANSLATED_KEYS: &[&str] = &[
    "name",
    "group",
    "protocol",
    "server",
    "username",
    "domain",
    "viewonly",
    "disableclipboard",
    "resolution_width",
    "resolution_height",
    "colordepth",
    "quality",
];

/// Parse a `.remmina` file text into an [`ImportedRemmina`].
///
/// Pure. No filesystem, no environment, no network.
pub fn parse_remmina(text: &str) -> Result<ImportedRemmina, RemminaParseError> {
    let _budget = crate::import_source::RetainedBudget::open();
    if !crate::import_source::lines_within_bounds(text) {
        return Err(RemminaParseError::TooComplex);
    }
    // `collect_entries` admits every value against the import bounds, so the
    // built profile needs no later audit.
    let (in_section, entries) = collect_entries(text)?;
    if !in_section {
        return Err(RemminaParseError::NoConnectionSection);
    }

    // ---- Required fields --------------------------------------------------
    let server = entries
        .iter()
        .find_map(|(k, v)| (k == "server").then_some(v.as_str()))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(RemminaParseError::NoServer)?;

    // Remmina puts the port inside `server=host:port`. A malformed suffix keeps
    // the raw server text as `host` and the default port, rather than guessing.
    let (host, port_from_server) = split_server(server);

    let protocol = entries
        .iter()
        .find_map(|(k, v)| (k == "protocol").then_some(v.as_str()))
        .map(remmina_protocol_to_ours)
        .unwrap_or(Protocol::Vnc);

    let mut profile = ConnectionProfile::new(String::new(), protocol, host.to_owned());
    profile.port = port_from_server.unwrap_or_else(|| protocol.default_port());

    let mut unsupported: Vec<String> = Vec::new();
    let mut omitted_warnings: usize = 0;
    let mut has_reported_password = false;

    // ---- Translate everything else, in file order -------------------------
    for (key, value) in &entries {
        let value_trim = value.trim();
        match key.as_str() {
            "name" => profile.name = value_trim.to_owned(),
            "group" => profile.group = value_trim.to_owned(),
            "protocol" | "server" => {
                // Consumed above; skipping here keeps them out of the
                // unsupported report.
            }
            "username" => profile.username = value_trim.to_owned(),
            "domain" => {
                profile.domain = if value_trim.is_empty() {
                    None
                } else {
                    Some(value_trim.to_owned())
                };
            }
            "viewonly" => profile.view_only = parse_bool(value_trim),
            "disableclipboard" => profile.disable_clipboard = parse_bool(value_trim),
            "resolution_width" | "resolution_height" => {
                // Folded into `resolution` after the loop, once both keys are known.
            }
            "colordepth" => match value_trim.parse::<u8>() {
                Ok(d) => profile.color_depth = d,
                Err(_) => report_bounded(&mut unsupported, &mut omitted_warnings, key, value_trim),
            },
            "quality" => match value_trim.parse::<u8>() {
                Ok(q) => profile.quality = q.min(9),
                Err(_) => report_bounded(&mut unsupported, &mut omitted_warnings, key, value_trim),
            },
            "password" if !value_trim.is_empty() => {
                // Not decrypted and not stored (see the module docs); reported instead.
                has_reported_password = true;
                report_bounded(
                    &mut unsupported,
                    &mut omitted_warnings,
                    "password",
                    "(present, not imported)",
                );
            }
            "password" => {
                // Empty `password=` line; nothing to report, nothing to do.
            }
            other => {
                report_bounded(&mut unsupported, &mut omitted_warnings, other, value_trim);
            }
        }
    }

    // ---- Fold resolution --------------------------------------------------
    let width = entries
        .iter()
        .find_map(|(k, v)| (k == "resolution_width").then_some(v.trim()))
        .and_then(|s| s.parse::<u32>().ok());
    let height = entries
        .iter()
        .find_map(|(k, v)| (k == "resolution_height").then_some(v.trim()))
        .and_then(|s| s.parse::<u32>().ok());
    match (width, height) {
        (Some(w), Some(h)) => profile.resolution = Some((w, h)),
        (Some(_), None) => {
            report_bounded(
                &mut unsupported,
                &mut omitted_warnings,
                "resolution_width",
                "(no matching resolution_height)",
            );
        }
        (None, Some(_)) => {
            report_bounded(
                &mut unsupported,
                &mut omitted_warnings,
                "resolution_height",
                "(no matching resolution_width)",
            );
        }
        (None, None) => {}
    }

    // ---- Default the name if the source did not carry one -----------------
    if profile.name.trim().is_empty() {
        profile.name = if profile.port == profile.protocol.default_port() {
            profile.host.clone()
        } else {
            format!("{}:{}", profile.host, profile.port)
        };
    }

    Ok(ImportedRemmina {
        profile,
        unsupported,
        omitted_warnings,
        has_reported_password,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Walk the text and collect `(key, value)` pairs from the `[remmina]`
/// section, dropping comments (`#` / `;`) and blank lines.
///
/// Returns `(saw_section, entries)` to distinguish an empty file from a
/// section with no keys.
fn collect_entries(text: &str) -> Result<(bool, Vec<(String, String)>), RemminaParseError> {
    let mut in_section = false;
    let mut saw_section = false;
    let mut entries = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            if let Some(name) = rest.strip_suffix(']') {
                in_section = name.trim().eq_ignore_ascii_case("remmina");
                if in_section {
                    saw_section = true;
                }
            }
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            // The count first, so a section of thousands of keys is refused
            // before the next pair is copied; then the pair itself, so the
            // list never holds a key or a value this build will not retain.
            if entries.len() >= crate::import_source::MAX_IMPORT_ENTRIES {
                crate::import_source::note_overflow(crate::import_source::RetentionBound::Count);
                return Err(RemminaParseError::TooComplex);
            }
            let key = k.trim();
            if !crate::import_source::admit_field(key) || !crate::import_source::admit_field(v) {
                return Err(RemminaParseError::TooComplex);
            }
            entries.push((key.to_ascii_lowercase(), v.to_string()));
        }
    }
    Ok((saw_section, entries))
}

/// Map Remmina's protocol names to ours. Remmina writes them uppercase
/// (`RDP`, `SPICE`, ...); anything unknown falls through to VNC — the
/// same tolerance `Protocol::from_key` extends to imports.
fn remmina_protocol_to_ours(text: &str) -> Protocol {
    match text.trim().to_ascii_uppercase().as_str() {
        "RDP" => Protocol::Rdp,
        "SPICE" => Protocol::Spice,
        "SSH" | "SFTP" => Protocol::Ssh,
        "NX" | "XDMCP" | "VNC" | "VNCI" => Protocol::Vnc,
        _ => Protocol::Vnc,
    }
}

/// Split `host:port` or a bare host. Returns `(host, Some(port))` if a
/// numeric port suffix is present and parses; `(input_verbatim, None)`
/// for a bare host or a malformed suffix.
fn split_server(input: &str) -> (&str, Option<u16>) {
    match input.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h, Some(port)),
            Err(_) => (input, None),
        },
        None => (input, None),
    }
}

/// Remmina booleans are the INI `1`/`0` shape, with `true`/`false` also
/// tolerated — GNOME Connections writes the second form.
fn parse_bool(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Append a bounded `key = value` warning line to the unsupported list, or
/// bump the omitted counter when the population cap has been reached.
///
/// Past the cap, each key only increments `omitted_warnings`, so a hostile
/// file cannot grow the vector while the banner still names the omission.
fn report_bounded(list: &mut Vec<String>, omitted: &mut usize, key: &str, value: &str) {
    if list.len() >= MAX_WARNING_ENTRIES {
        *omitted = (*omitted).saturating_add(1);
        return;
    }
    list.push(bound_warning_line(key, value));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_VNC: &str = "\
[remmina]
name=Prod VNC
protocol=VNC
server=10.0.0.5:5901
username=admin
group=Work/Servers
viewonly=1
resolution_width=1920
resolution_height=1080
colordepth=32
quality=6
";

    const WITH_UNSUPPORTED_AND_PASSWORD: &str = "\
[remmina]
name=Legacy Box
protocol=RDP
server=legacy.example.com:3389
username=alice
domain=EXAMPLE
password=.enc.hex.blob
disableclipboard=1
# Remmina keys this importer does not translate:
ssh_enabled=1
ssh_server=jump.example.com
ssh_username=alice
audio-output=off
keymap=us
glyph-cache=1
";

    #[test]
    fn minimal_profile_translates_every_supported_field_and_related_cases() {
        {
            let out = parse_remmina(MINIMAL_VNC).unwrap();
            let p = &out.profile;
            assert_eq!(p.name, "Prod VNC");
            assert_eq!(p.group, "Work/Servers");
            assert_eq!(p.protocol, Protocol::Vnc);
            assert_eq!(p.host, "10.0.0.5");
            assert_eq!(p.port, 5901);
            assert_eq!(p.username, "admin");
            assert!(p.view_only);
            assert_eq!(p.resolution, Some((1920, 1080)));
            assert_eq!(p.color_depth, 32);
            assert_eq!(p.quality, 6);
            assert!(
                !p.has_keyring_password,
                "an import never claims a saved password"
            );
            assert!(out.unsupported.is_empty(), "got {:?}", out.unsupported);
            assert!(!out.has_reported_password);
        }

        {
            let out = parse_remmina(WITH_UNSUPPORTED_AND_PASSWORD).unwrap();
            // Fixture: password (reported), ssh_enabled, ssh_server, ssh_username,
            // audio-output, keymap, glyph-cache = 7 entries, each shown or omitted.
            let expected_total: usize = 7;
            let total = out.unsupported.len() + out.omitted_warnings;
            assert_eq!(
                total, expected_total,
                "total (shown + omitted) must account for every non-translated \
             source field; got shown={:?} omitted={}",
                out.unsupported, out.omitted_warnings,
            );
            // The cap drops from the tail, so `password`, the first untranslated key
            // in the fixture, must appear.
            assert!(
                out.unsupported.iter().any(|e| e.contains("password")),
                "file-order head: password must appear on the shown window; \
             got {:?}",
                out.unsupported,
            );
            assert!(
                out.unsupported.iter().any(|e| e.contains("ssh_enabled")),
                "file-order head: ssh_enabled must appear on the shown window; \
             got {:?}",
                out.unsupported,
            );
            // `glyph-cache` is the file-order LAST non-translated key and must
            // fall into the omitted count rather than displace an earlier line.
            assert!(
                !out.unsupported.iter().any(|e| e.contains("glyph-cache")),
                "file-order tail: the last field must fall into the omitted \
             count, not the shown window; got {:?}",
                out.unsupported,
            );
        }

        {
            let out = parse_remmina(WITH_UNSUPPORTED_AND_PASSWORD).unwrap();
            assert!(
                out.has_reported_password,
                "the has_reported_password flag must be set so the result \
             screen can name what did not come across"
            );
            assert!(
                out.unsupported
                    .iter()
                    .any(|e| e.contains("password") && e.contains("not imported")),
                "the report line must name password AND that it was not \
             imported: {:?}",
                out.unsupported
            );
            assert!(!out.profile.has_keyring_password);
        }

        {
            assert_eq!(
                parse_remmina("").unwrap_err(),
                RemminaParseError::NoConnectionSection
            );
            assert_eq!(
                parse_remmina("name=orphan").unwrap_err(),
                RemminaParseError::NoConnectionSection
            );
        }
    }

    #[test]
    fn a_file_without_a_server_line_is_refused_and_related_cases() {
        {
            assert_eq!(
                parse_remmina("[remmina]\nname=x\n").unwrap_err(),
                RemminaParseError::NoServer
            );
        }

        {
            let text = "[remmina]\nname=X\nprotocol=SSH\nserver=box\n";
            let out = parse_remmina(text).unwrap();
            assert_eq!(out.profile.host, "box");
            assert_eq!(out.profile.port, Protocol::Ssh.default_port());
        }

        {
            let text = "[remmina]\nprotocol=VNC\nserver=box:5901\n";
            let out = parse_remmina(text).unwrap();
            assert_eq!(out.profile.name, "box:5901");

            let text = "[remmina]\nprotocol=VNC\nserver=box\n";
            let out = parse_remmina(text).unwrap();
            assert_eq!(out.profile.name, "box", "default-port elision applies");
        }

        {
            for key in TRANSLATED_KEYS {
                // `server` is required, and the resolution pair is covered by
                // `minimal_profile_translates_every_supported_field` and
                // `unsupported_fields_are_reported_not_dropped`.
                if matches!(*key, "server" | "resolution_width" | "resolution_height") {
                    continue;
                }
                let text = format!("[remmina]\nserver=box\nprotocol=VNC\n{key}=1\n");
                let out = parse_remmina(&text).unwrap();
                assert!(
                    !out.unsupported
                        .iter()
                        .any(|e| e.starts_with(&format!("{key} "))),
                    "{key} claims to be translated but appears in the \
                 unsupported report for {text:?}: {:?}",
                    out.unsupported
                );
            }
        }
    }

    #[test]
    fn a_very_long_unsupported_value_is_truncated_at_a_codepoint_boundary_and_related_cases() {
        {
            let long: String = "é".repeat(200);
            let text = format!("[remmina]\nserver=box\nprotocol=VNC\nmystery={long}\n");
            let out = parse_remmina(&text).unwrap();
            let line = out
                .unsupported
                .iter()
                .find(|e| e.starts_with("mystery = "))
                .expect("the mystery key must be reported");
            assert!(line.ends_with('\u{2026}'));
            assert!(
                line.chars().count() < long.chars().count() + 10,
                "the value should be truncated: {line}"
            );
        }

        {
            let text = "\
[remmina]
# this is a comment
; this too

name=X
protocol=VNC
server=box
";
            let out = parse_remmina(text).unwrap();
            assert!(out.unsupported.is_empty(), "{:?}", out.unsupported);
        }

        {
            let text = "[remmina]\nprotocol=VNC\nserver=box:not-a-port\n";
            let out = parse_remmina(text).unwrap();
            assert_eq!(out.profile.host, "box:not-a-port");
            assert_eq!(out.profile.port, Protocol::Vnc.default_port());
        }
    }
}
