//! Bounded, single-line projections for imported text shown by the app.
//!
//! Profile names remain unchanged in the model. Callers use
//! [`bound_display_name`] only where a name is presented. Remmina warnings are
//! bounded separately by population, key/value line length, and aggregate
//! announcement length.

use std::borrow::Cow;

/// Maximum bytes in a displayed profile name.
pub const MAX_DISPLAY_BYTES: usize = 64;

pub(crate) const MAX_PATH_DISPLAY_BYTES: usize = 64;

/// Text shown when a name contains no visible characters after scrubbing.
pub const STABLE_DISPLAY_FALLBACK: &str = "Untitled connection";

/// Maximum bytes in a displayed sidebar group heading.
pub const MAX_GROUP_HEADING_BYTES: usize = 64;

/// Heading shown when an imported folder value has no visible characters after
/// scrubbing. The stored `group` string is preserved verbatim as the bucket
/// key, so two distinct all-unsafe folders remain distinct buckets even though
/// both paint this stable fallback.
pub const STABLE_GROUP_FALLBACK: &str = "Unnamed group";

/// Maximum bytes in a displayed host, before any `:port` suffix.
pub const MAX_HOST_DISPLAY_BYTES: usize = 48;

/// Host text shown when an imported host has no visible characters after
/// scrubbing. The stored `host`/`port` are preserved verbatim for search,
/// export, editing and connection dispatch.
pub const STABLE_HOST_FALLBACK: &str = "(no host)";

/// Maximum bytes in one displayed `key = value` warning.
pub const MAX_WARNING_LINE_BYTES: usize = 64;

/// Maximum number of parsed warning lines retained for presentation.
pub const MAX_WARNING_ENTRIES: usize = 3;

/// Maximum bytes in the complete warning announcement body.
///
/// This permits the authored introduction, at least one maximum-length warning
/// line, an omitted-fields notice, and the password notice. A parser-produced
/// worst case therefore reaches this independent aggregate bound without
/// losing either mandatory notice.
pub const MAX_AGGREGATE_BODY_BYTES: usize = 384;

const ELLIPSIS: char = '\u{2026}';
const PASSWORD_NOTICE: &str = "The source's password was NOT imported — no credential is stored for this profile. Save it from the connection form.";

#[inline]
fn is_stripped(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// Replace controls, bidi formatting, and every whitespace run with one ASCII
/// space, then trim the ends.
fn scrub(raw: &str) -> Cow<'_, str> {
    let mut out = String::with_capacity(raw.len());
    let mut pending_space = false;

    for c in raw.chars() {
        if is_stripped(c) || c.is_whitespace() {
            pending_space = !out.is_empty();
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(c);
        }
    }

    if out == raw {
        Cow::Borrowed(raw)
    } else {
        Cow::Owned(out)
    }
}

fn truncate_with_ellipsis(s: &str, cap: usize) -> String {
    debug_assert!(cap >= ELLIPSIS.len_utf8());
    if s.len() <= cap {
        return s.to_string();
    }
    let budget = cap.saturating_sub(ELLIPSIS.len_utf8());
    let mut end = budget;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(cap);
    out.push_str(&s[..end]);
    out.push(ELLIPSIS);
    debug_assert!(out.len() <= cap);
    out
}

/// Return a bounded, single-line profile name suitable for presentation.
#[must_use]
pub fn bound_display_name(raw: &str) -> String {
    let cleaned = scrub(raw);
    if cleaned.is_empty() {
        return STABLE_DISPLAY_FALLBACK.to_string();
    }
    truncate_with_ellipsis(&cleaned, MAX_DISPLAY_BYTES)
}

pub(crate) fn bound_path_name(raw: &str) -> String {
    let name = std::path::Path::new(raw)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(raw);
    let cleaned = scrub(name);
    if cleaned.is_empty() {
        return "selected file".to_string();
    }
    truncate_with_ellipsis(&cleaned, MAX_PATH_DISPLAY_BYTES)
}

/// Return a bounded, single-line sidebar group heading for presentation.
///
/// Callers use this only where a folder value is *painted* (a branch heading);
/// the stored `group` string remains the bucket key and membership identity, so
/// grouping, expansion toggling and export are unaffected. A folder that
/// scrubs to nothing falls back to [`STABLE_GROUP_FALLBACK`].
#[must_use]
pub fn bound_group_heading(raw: &str) -> String {
    let cleaned = scrub(raw);
    if cleaned.is_empty() {
        return STABLE_GROUP_FALLBACK.to_string();
    }
    truncate_with_ellipsis(&cleaned, MAX_GROUP_HEADING_BYTES)
}

/// Return a bounded, single-line `host` or `host:port` subtitle for
/// presentation.
///
/// The port is shown only when it differs from `default_port`, matching
/// [`crate::model::ConnectionProfile::host_display`]. Only the host is scrubbed
/// and byte-capped; the port is appended afterwards so a long host cannot swallow
/// it. Raw `host`/`port` remain for search, export, editing and dispatch.
#[must_use]
pub fn bound_host_display(host: &str, port: u16, default_port: u16) -> String {
    let cleaned = scrub(host);
    let host_shown = if cleaned.is_empty() {
        STABLE_HOST_FALLBACK.to_string()
    } else {
        truncate_with_ellipsis(&cleaned, MAX_HOST_DISPLAY_BYTES)
    };
    if port == default_port {
        host_shown
    } else {
        format!("{host_shown}:{port}")
    }
}

/// Render one independently bounded and scrubbed `key = value` warning.
#[must_use]
pub fn bound_warning_line(key: &str, value: &str) -> String {
    const SEP: &str = " = ";
    let cleaned_key = scrub(key);
    let key = if cleaned_key.is_empty() {
        "?".to_string()
    } else {
        truncate_with_ellipsis(&cleaned_key, MAX_WARNING_LINE_BYTES / 2)
    };
    let remaining = MAX_WARNING_LINE_BYTES.saturating_sub(key.len() + SEP.len());
    let value = truncate_with_ellipsis(&scrub(value), remaining);
    let line = format!("{key}{SEP}{value}");
    debug_assert!(line.len() <= MAX_WARNING_LINE_BYTES);
    line
}

fn omitted_warnings_notice(omitted: usize) -> Option<String> {
    (omitted != 0).then(|| {
        format!(
            "{omitted} more field{s} not shown.",
            s = if omitted == 1 { "" } else { "s" }
        )
    })
}

fn compose_warning_summary(
    warnings: &[String],
    parser_omitted: usize,
    shown: usize,
    has_reported_password: bool,
) -> String {
    let total = warnings.len().saturating_add(parser_omitted);
    let mut body = if total == 0 {
        "Saved as a new connection.".to_string()
    } else {
        format!(
            "Saved as a new connection. {total} field{s} did not come across and {were} left for you to review:",
            s = if total == 1 { "" } else { "s" },
            were = if total == 1 { "was" } else { "were" },
        )
    };
    for line in warnings.iter().take(shown) {
        body.push_str("\n  \u{2022} ");
        body.push_str(line);
    }

    let aggregate_omitted = parser_omitted.saturating_add(warnings.len() - shown);
    if let Some(notice) = omitted_warnings_notice(aggregate_omitted) {
        body.push_str("\n  \u{2026} ");
        body.push_str(&notice);
    }
    if has_reported_password {
        body.push_str("\n\n");
        body.push_str(PASSWORD_NOTICE);
    }
    body
}

/// Compose a bounded warning body while retaining omitted-field and password
/// notices. If the aggregate ceiling cannot fit every retained warning line,
/// lines are removed from the tail and included in the omitted count.
#[must_use]
pub fn bounded_warning_summary(
    warnings: &[String],
    parser_omitted: usize,
    has_reported_password: bool,
) -> String {
    for shown in (1..=warnings.len()).rev() {
        let body = compose_warning_summary(warnings, parser_omitted, shown, has_reported_password);
        if body.len() <= MAX_AGGREGATE_BODY_BYTES {
            return body;
        }
    }

    let notices_only = compose_warning_summary(warnings, parser_omitted, 0, has_reported_password);
    debug_assert!(notices_only.len() <= MAX_AGGREGATE_BODY_BYTES);
    notices_only
}

#[cfg(test)]
mod tests {}
