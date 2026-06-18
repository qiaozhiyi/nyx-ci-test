//! Nyx operator GUI — credential vault table (G2 display widget).
//!
//! Pure display widget for harvested credentials. Each row shows source
//! (beacon id or `localhost`), principal/realm, kind (hash/password/ticket/key),
//! and the secret value.
//!
//! By design the secret value is **never rendered to screen in full**. It is
//! masked via [`mask_secret`] (first two + last two chars with `••••` between,
//! or bare `••••` for short secrets) so credentials are never casually exposed
//! on screen, in screenshots, or in recordings. This masking is a deliberate,
//! always-on safety default — not a toggle.
//!
//! Secret reveal and copy-to-clipboard arrive in G4; this file contains only
//! the read-only display widget + its backing shared state. Data lives in the
//! process-global [`CREDS`], the same Makepad idiom as `SessionList`/`LogList`.

use makepad_widgets::*;
use std::sync::{LazyLock, RwLock};

// ── shared credential store ─────────────────────────────────────────────────

pub static CREDS: LazyLock<RwLock<Vec<CredEntry>>> = LazyLock::new(|| RwLock::new(Vec::new()));

#[derive(Clone, Copy, Debug)]
pub enum CredKind {
    Hash,
    Password,
    Ticket,
    Key,
}

#[derive(Clone, Debug)]
pub struct CredEntry {
    pub source: String,
    pub principal: String,
    pub kind: CredKind,
    pub secret: String,
}

/// Mask a secret for on-screen display.
///
/// * `len <= 4`  → `••••`
/// * otherwise   → first two chars + `••••` + last two chars
///
/// Operates on Unicode scalar values (not bytes) so multi-byte secrets don't
/// panic. For the ASCII secrets that dominate red-team tooling this is
/// identical to a byte-length check.
pub fn mask_secret(s: &str) -> String {
    const MASK: &str = "••••";
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 4 {
        return MASK.to_string();
    }
    let n = chars.len();
    let mut out = String::with_capacity(2 + MASK.len() + 2);
    out.extend(&chars[..2]);
    out.push_str(MASK);
    out.extend(&chars[n - 2..]);
    out
}

/// Lowercase one-word label for a [`CredKind`], as shown in the `kind` column.
pub fn kind_label(k: &CredKind) -> &'static str {
    match k {
        CredKind::Hash => "hash",
        CredKind::Password => "password",
        CredKind::Ticket => "ticket",
        CredKind::Key => "key",
    }
}

// ── CredTable widget (virtualized, reads CREDS global) ───────────────────────

#[derive(Script, ScriptHook, Widget)]
pub struct CredTable {
    #[deref]
    view: View,
}

impl Widget for CredTable {
    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        let creds = CREDS.read().unwrap().clone();
        while let Some(step) = self.view.draw_walk(cx, scope, walk).step() {
            if let Some(mut list) = step.as_portal_list().borrow_mut() {
                if creds.is_empty() {
                    list.set_item_range(cx, 0, 0);
                } else {
                    list.set_item_range(cx, 0, creds.len());
                    while let Some(item_id) = list.next_visible_item(cx) {
                        let Some(c) = creds.get(item_id) else { continue };
                        let item = list.item(cx, item_id, id!(Item));
                        item.label(cx, ids!(source)).set_text(cx, &c.source);
                        item.label(cx, ids!(principal)).set_text(cx, &c.principal);
                        item.label(cx, ids!(kind)).set_text(cx, kind_label(&c.kind));
                        item.label(cx, ids!(value)).set_text(cx, &mask_secret(&c.secret));
                        item.draw_all_unscoped(cx);
                    }
                }
            }
        }
        DrawStep::done()
    }

    fn handle_event(&mut self, cx: &mut Cx, event: &Event, scope: &mut Scope) {
        self.view.handle_event(cx, event, scope);
    }
}

#[cfg(test)]
mod tests {
    use super::{kind_label, mask_secret, CredKind};

    #[test]
    fn short_secret_fully_masked() {
        // <= 4 chars → bare dots, never revealing any of it.
        assert_eq!(mask_secret(""), "••••");
        assert_eq!(mask_secret("a"), "••••");
        assert_eq!(mask_secret("ab"), "••••");
        assert_eq!(mask_secret("abcd"), "••••");
    }

    #[test]
    fn long_secret_keeps_only_first_and_last_two() {
        assert_eq!(mask_secret("abcde"), "ab••••de");
        assert_eq!(mask_secret("secret123"), "se••••23");
    }

    #[test]
    fn mask_does_not_leak_middle() {
        let masked = mask_secret("P@ssw0rd!");
        assert!(masked.contains("••••"));
        // First two and last two may appear, but the middle must be masked.
        assert!(!masked.contains("ssw"));
    }

    #[test]
    fn multibyte_secret_does_not_panic() {
        // Unicode scalar path; must not index mid-codepoint.
        let _ = mask_secret("密码123456");
    }

    #[test]
    fn kind_labels() {
        assert_eq!(kind_label(&CredKind::Hash), "hash");
        assert_eq!(kind_label(&CredKind::Password), "password");
        assert_eq!(kind_label(&CredKind::Ticket), "ticket");
        assert_eq!(kind_label(&CredKind::Key), "key");
    }
}
