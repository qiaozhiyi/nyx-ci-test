//! DSL palette tokens — the single color/metric namespace every view and
//! widget script block imports via `use mod.nyx.*`.
//!
//! MIRROR CONSTRAINT (theme.rs): every `C*` color here must equal its twin in
//! `Palette::dark()` (theme.rs) so a cold first paint matches the dynamic
//! recolor `apply_theme` applies afterwards. If you change a color here,
//! change its twin in theme.rs — and vice-versa. Layout metrics (`Cpad`,
//! `Cgap`, radii) are DSL-only and have no theme.rs twin.

use makepad_widgets::*;

script_mod! {
    mod.nyx = {
        // ── Violet Dark palette (2026-07-16 reskin) ────────────────────────
        Cbg:       #x0D0E12  // app background — deepest surface
        Cinput:    #x1B1E26  // input fill (= card surface)
        Cinput_b:  #x3A3F4C  // visible input border
        Cbar:      #x181A21  // recessed secondary bars / tab bar
        Cpanel:    #x14161B  // side panels + event-log shell
        Crow:      #x14161B  // table/data-row base
        Crowhov:   #x1F2330  // row hover
        Crowsel:   #x2E2849  // row selected (violet tint)
        Celev:     #x1B1E26  // brightest surface — column headers / dialog card
        Cborder:   #x262A35  // hairline dividers
        Cprimary:  #xE2E4EA  // primary text
        Csecond:   #x9BA0AE  // secondary text
        Cmuted:    #x6B707E  // muted text / column labels
        Caccent:   #x8B7CF6  // violet accent
        Cacchov:   #xA395FF  // accent hover
        Conaccent: #xFFFFFF  // text/icons drawn ON the accent color
        Csuccess:  #x3FB68B  // success / online (soft teal)
        Cdanger:   #xE5534B  // danger / alert
        Cwarn:     #xD9A036  // warning / pending / secrets
        Cinfo:     #x5EB1EF  // info / command keyword
        // ── layout metrics (no theme.rs twin) ──────────────────────────────
        Cradius:   6.0       // unified corner radius (buttons / inputs)
        Cradius_l: 8.0       // large radius (cards / dialogs)
        Cradius_s: 4.0       // small radius (tags / badges)
        // Shared layout metrics so column headers and data rows stay perfectly
        // aligned: both reference these instead of re-typing the same numbers.
        Cpad:      14.0      // table row / header horizontal inset
        Cgap:      16.0      // column gap inside rows / headers
    }
}
