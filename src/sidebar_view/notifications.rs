//! State-backed, dismissible notification toasts.

use super::*;

pub(crate) const IMPORT_IN_FLIGHT_TOAST: &str = "remote-app-import-in-flight";
pub(crate) const TRANSFER_RESULT_TOAST: &str = "remote-app-transfer-result";
pub(crate) const WOL_TOAST: &str = "remote-app-wol-status";
pub(crate) const CREDENTIAL_TOAST: &str = "remote-app-credential-notice";

pub fn transfer_toast(app: &App) -> Option<Element<'_, Message>> {
    use enzui_iced_widgets::toast::{ToastTone, enz_toast};

    // A refused concurrent import takes precedence over the earlier pending read.
    let refused = app
        .transfer_result
        .as_ref()
        .is_some_and(crate::app_state::TransferResult::is_error);
    if let Some(flight) = app.import_in_flight.as_ref().filter(|_| !refused) {
        return Some(
            enz_toast(flight.target.importing_title(), Message::ImportCancel)
                .description(
                    "Reading the file you chose. Nothing has been added to \
                     your connections yet.",
                )
                .tone(ToastTone::Info)
                .action("Cancel import", Message::ImportCancel)
                .id(IMPORT_IN_FLIGHT_TOAST)
                .into_element(),
        );
    }
    let result = app.transfer_result.as_ref()?;
    Some(
        enz_toast(result.title(), Message::DismissTransferResult)
            .description(result.body())
            .tone(if result.is_error() {
                ToastTone::Error
            } else {
                ToastTone::Success
            })
            .id(TRANSFER_RESULT_TOAST)
            .into_element(),
    )
}

pub fn wol_toast(app: &App) -> Option<Element<'_, Message>> {
    use enzui_iced_widgets::toast::{ToastTone, enz_toast};

    let status = app.wol_status.as_ref()?;
    let mut toast =
        enz_toast(status.title(), Message::DismissWolStatus).tone(if status.is_error() {
            ToastTone::Error
        } else {
            ToastTone::Success
        });
    if let Some(body) = status.body() {
        toast = toast.description(body);
    }
    Some(toast.id(WOL_TOAST).into_element())
}

pub fn credential_toast(app: &App) -> Option<Element<'_, Message>> {
    use enzui_iced_widgets::toast::{ToastTone, enz_toast};

    let notice = app.credential_notice.as_ref()?;
    Some(
        enz_toast(notice.title.clone(), Message::DismissCredentialNotice)
            .description(notice.body.clone())
            .tone(if notice.is_error {
                ToastTone::Error
            } else {
                ToastTone::Info
            })
            .id(CREDENTIAL_TOAST)
            .into_element(),
    )
}

pub fn db_boot_error_toast(app: &App) -> Option<Element<'_, Message>> {
    use crate::db::DbBootErrorKind;
    use enzui_iced_widgets::toast::{ToastTone, enz_toast};

    app.db_boot_error.as_ref()?;
    if app.db_notice_dismissed {
        return None;
    }
    let body: &'static str = match app.db_boot_error_kind {
        Some(DbBootErrorKind::Migration) => {
            "Remote could not relocate its saved connections to the destination \
             on disk. The connection library came up in memory instead, and \
             any changes you make now apply to this session only — they will \
             not be saved when Remote closes."
        }
        Some(DbBootErrorKind::NoDataHome) => {
            "Remote could not find a writable user data directory \
             ($XDG_DATA_HOME/$HOME is unset or invalid), so the connection \
             library came up in memory. Any changes you make now apply to \
             this session only — they will not be saved when Remote closes."
        }
        Some(DbBootErrorKind::CreateDataDir) => {
            "Remote could not create its user data directory, so the connection \
             library came up in memory. Any changes you make now apply to \
             this session only — they will not be saved when Remote closes."
        }
        Some(DbBootErrorKind::Open) => {
            "Remote could not open its saved connections database, so the \
             library came up in memory. Any changes you make now apply to \
             this session only — they will not be saved when Remote closes."
        }
        Some(DbBootErrorKind::InvalidAppId) | None => {
            "Remote could not open its saved connections database. Any \
             changes you make now apply to this session only — they will \
             not be saved when Remote closes."
        }
    };

    Some(
        enz_toast(
            "Saved connections are not being written to disk",
            Message::DismissDbNotice,
        )
        .description(body)
        .tone(ToastTone::Error)
        .id("remote-app-db-boot-error")
        .into_element(),
    )
}

pub fn close_hold_toast(app: &App) -> Option<Element<'_, Message>> {
    use crate::rfb::backend::VncCloseProgress;
    use enzui_iced_widgets::toast::{ToastTone, enz_toast};

    if !app.close_is_held() {
        return None;
    }
    let owed = app.vnc_close_notices.len() + app.desktop_close_notices.len();
    let unconfirmed = app
        .vnc_close_notices
        .iter()
        .filter(|debt| debt.progress == VncCloseProgress::Unknown)
        .count();
    let failed = unconfirmed;
    let body = match (owed, unconfirmed) {
        (0, _) => "Remote is finishing what its connections were doing.".to_owned(),
        (owed, 0) => {
            format!("{owed} connection(s) are still closing. Remote will close when they have.")
        }
        (owed, unconfirmed) => format!(
            "{owed} connection(s) are still closing, and {unconfirmed} were severed without their workers' shutdown being confirmed."
        ),
    };
    let overdue = app.close_is_overdue();
    let mut toast = enz_toast(
        if failed > 0 && overdue {
            "Remote could not close every connection"
        } else {
            "Remote is closing"
        },
        Message::WindowCloseVeto,
    )
    .description(body)
    .tone(if failed > 0 && overdue {
        ToastTone::Error
    } else {
        ToastTone::Info
    })
    .id("remote-app-close-hold");
    if overdue {
        toast = toast.action("Retry", Message::WindowCloseRetry);
    }
    Some(toast.into_element())
}
