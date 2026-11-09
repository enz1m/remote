//! Sidebar organisation: how the saved connections are grouped.
//!
//! Grouping is by folder only, and folders are flat: `p.group` is a bucket name,
//! so `Home/Legacy` is its own folder, not a child of `Home`. [`grouped`] takes no
//! mode.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use uuid::Uuid;

use crate::model::ConnectionProfile;

/// The empty folder key, distinct from a folder named "Ungrouped".
pub const UNGROUPED: &str = "";

/// Canonical bucket key for a stored folder value.
pub(crate) fn group_key(group: &str) -> String {
    if group.trim().is_empty() {
        UNGROUPED.to_string()
    } else {
        group.trim().to_string()
    }
}

// ---------------------------------------------------------------------------
// Grouping
// ---------------------------------------------------------------------------

/// One bucket of profiles under a header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupBucket {
    /// The bucket key and label: the profile's folder, or the synthetic
    /// [`UNGROUPED`] fallback. Folders are flat, so these are the same string.
    pub name: String,
    /// Whether the section is open.
    pub expanded: bool,
    /// The profiles in it, in display order.
    pub profile_ids: Vec<Uuid>,
}

/// Expansion state for real folder buckets.
///
/// `All` is the initial state. Once a folder is toggled, `Only` records the
/// exact set of open folders. Keeping the mode in the type is important:
/// `Only(empty)` means every folder is collapsed, while `All` means every
/// folder is expanded. An untyped empty set cannot distinguish those states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupExpansion(ExpansionMode);

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExpansionMode {
    All,
    Only(HashSet<String>),
}

impl Default for GroupExpansion {
    fn default() -> Self {
        Self(ExpansionMode::All)
    }
}

impl GroupExpansion {
    /// Whether the named bucket is currently open.
    pub fn is_expanded(&self, name: &str) -> bool {
        match &self.0 {
            ExpansionMode::All => true,
            ExpansionMode::Only(expanded) => expanded.contains(name),
        }
    }

    /// Toggle one bucket while preserving every other bucket's state.
    ///
    /// On the first toggle, callers supply the current bucket keys so the default-open
    /// state becomes an explicit set first. `Only(empty)` represents a collapsed
    /// single-folder library. A key not in the current library is ignored.
    pub fn toggle(&mut self, key: String, current_keys: impl IntoIterator<Item = String>) {
        let current: HashSet<String> = current_keys.into_iter().collect();
        if !current.contains(&key) {
            return;
        }

        match &mut self.0 {
            ExpansionMode::All => {
                let mut expanded = current;
                expanded.remove(&key);
                self.0 = ExpansionMode::Only(expanded);
            }
            ExpansionMode::Only(expanded) => {
                if !expanded.remove(&key) {
                    expanded.insert(key);
                }
            }
        }
    }
}

/// The full grouped view: a favourites pseudo-bucket plus the real buckets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Grouping {
    /// Starred profiles, surfaced at the top regardless of bucket.
    pub favorites: Vec<Uuid>,
    pub buckets: Vec<GroupBucket>,
}

impl Grouping {
    /// Distinct profiles across all buckets.
    pub fn profile_count(&self) -> usize {
        self.buckets
            .iter()
            .flat_map(|b| b.profile_ids.iter())
            .collect::<BTreeSet<_>>()
            .len()
    }
}

/// Build the grouped view.
///
/// [`GroupExpansion`] carries user-toggled expansion across rebuilds. Its
/// typed `All` state makes the first render open without overloading an empty
/// set, while `Only(empty)` can represent a fully collapsed library.
///
/// Unfiled profiles precede alphabetised folders and remain expanded.
pub fn grouped(profiles: &[ConnectionProfile], expansion: &GroupExpansion) -> Grouping {
    let mut favorites: Vec<&ConnectionProfile> = profiles.iter().filter(|p| p.favorite).collect();
    favorites.sort_by_key(|p| p.name.to_lowercase());
    let favorite_ids: Vec<Uuid> = favorites.into_iter().map(|p| p.id).collect();

    let mut byname: BTreeMap<String, Vec<&ConnectionProfile>> = BTreeMap::new();
    for p in profiles {
        byname.entry(group_key(&p.group)).or_default().push(p);
    }

    let mut buckets: Vec<GroupBucket> = byname
        .into_iter()
        .map(|(name, mut ps)| {
            ps.sort_by_key(|p| p.name.to_lowercase());
            let is_expanded = name == UNGROUPED || expansion.is_expanded(&name);
            GroupBucket {
                name,
                expanded: is_expanded,
                profile_ids: ps.into_iter().map(|p| p.id).collect(),
            }
        })
        .collect();

    buckets.sort_by(|a, b| {
        let (a_synthetic, b_synthetic) = (a.name == UNGROUPED, b.name == UNGROUPED);
        match (a_synthetic, b_synthetic) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        }
    });

    Grouping {
        favorites: favorite_ids,
        buckets,
    }
}

// ---------------------------------------------------------------------------
// Empty states
// ---------------------------------------------------------------------------

/// The empty state for "there are saved profiles, but none match the current
/// filter".
///
/// Distinct from having no profiles: a filtered empty asks the user to change the
/// query, an unfiltered one to add a connection.
pub const NO_MATCHING: &str = "No matching connections";

/// The empty state for "this connection has no port-forward rules".
pub const NO_FORWARDING_RULES: &str = "No forwarding rules configured.";

/// The empty state for a library with no saved connections at all.
pub const NO_CONNECTIONS: &str = "No saved connections";

/// Which empty state a list should show, or `None` when it has rows.
///
/// The two arguments are deliberately separate counts rather than one
/// "is_empty" bool: `total > 0 && shown == 0` is the *filtered* empty and is a
/// different message from `total == 0`. Collapsing them tells a user with
/// twenty saved connections that they have none.
pub fn list_empty_state(total: usize, shown: usize) -> Option<&'static str> {
    match (total, shown) {
        (_, n) if n > 0 => None,
        (0, _) => Some(NO_CONNECTIONS),
        _ => Some(NO_MATCHING),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {}
