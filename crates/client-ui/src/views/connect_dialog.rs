//! Connect dialog (shown until connected) + the connecting overlay that masks
//! the 420→1280 resize snap, plus the Rust-side form validation/error routing.
//!
//! DSL notes carried over from the pre-split main.rs:
//! * connect_view / connect_card / logo_box are plain View, NOT SolidView. In
//!   Makepad 2.0 `self.ui.view()` returns the wrong widget type for a
//!   SolidView, and a `script_apply_eval!` through it silently writes garbage
//!   to draw_bg — which is why Light mode never recoloured the card in v1.
//!   View supports the same draw_bg.color / border_radius / border_color
//!   surface props AND repaints correctly via apply_theme(). Keep these three
//!   as View.
//! * Inputs BLEND with the card (fill = elev) — no lighter/darker patch
//!   fighting the surface. The field boundary is carried entirely by a clearly
//!   visible 1px border (GitHub-dark input pattern). Saturated accent lights
//!   up ONLY on focus — one signal, not three boxes.
//! * Each field is a Down column: label / input / (error or helper) — inline
//!   errors live right under the field they describe, never stacked at the
//!   bottom.

use makepad_widgets::*;

use crate::bridge;

script_mod! {
    use mod.prelude.widgets.*
    use mod.widgets.*
    use mod.nyx.*

    // ── connect overlay progress bar (shader) ───────────────────────────────
    // A named top-level shader component — Makepad's DSL requires pixel-fn
    // components to be standalone definitions so the Script system can compile
    // them. Referenced as `connect_progress := ConnectProgress` inside the
    // connecting overlay. 14 cells; a wave head travels L→R lighting cells with
    // the soft-teal success color; driven by self.draw_pass.time.
    let ConnectProgress = View{
        show_bg: true
        draw_bg +: {
            // 0 = flowing green, 1 = solid success, 2 = red fail (Rust-driven).
            state: instance(0.0)
            green: instance(Csuccess)
            red: instance(Cdanger)
            track: instance(Cborder)

            pixel: fn() {
                let cells = 14.0
                let cell_i = floor(self.pos.x * cells)
                let cell_center = (cell_i + 0.5) / cells
                // wave head travels L→R, looping every 1.4s
                let period = 1.4
                let wave = modf(self.draw_pass.time, period) / period
                let d = abs(cell_center - wave)
                let intensity = smoothstep(0.22, 0.0, d)
                // state partition: flow(0) / success(1) / fail(2)
                let red_mode = step(1.5, self.state)
                let solid_mode = step(0.5, self.state) * (1.0 - red_mode)
                let col = mix(self.green.rgb, self.red.rgb, red_mode)
                // flow: the wave lights cells; success+fail: solid full-lit
                // (a steady red reads as a terminal failure better than a pulse)
                let lit = mix(intensity, 1.0, max(solid_mode, red_mode))
                return vec4(mix(self.track.rgb, col, lit), 1.0)
            }
        }
    }

    // ── connect dialog (shown until connected) ──────────────────────────────
    mod.nyx.ConnectDialog = SolidView{
        width: Fill height: Fill
        padding: Inset{top: 0.0 left: 0.0 right: 0.0}
        flow: Down spacing: 0
        draw_bg.color: Cbg
        connect_card := View{
            show_bg: true
            width: Fill height: Fill
            flow: Down
            // Floating card on the deep window bg: elev surface,
            // large radius, 1px hairline, margin all around so
            // the Cbg backdrop frames it.
            margin: Inset{top: 16.0 bottom: 16.0 left: 16.0 right: 16.0}
            draw_bg.color: Celev
            draw_bg.border_radius: Cradius_l
            draw_bg.border_color: Cborder
            draw_bg.border_size: 1.0

            // Brand header — compact.
            View{
                width: Fill height: Fit
                padding: Inset{top: 12.0 bottom: 6.0 left: 20.0 right: 20.0}
                flow: Down spacing: 2.0
                View{
                    width: Fit height: Fit
                    flow: Right spacing: 8.0
                    align: Align{y: 0.5}
                    logo_box := RoundedView{
                        width: 32 height: 32
                        draw_bg.color: Caccent
                        draw_bg.border_radius: 8.0
                        align: Align{x: 0.5, y: 0.5}
                        logo_letter := Label{
                            text: "N"
                            draw_text.color: Conaccent
                            draw_text.text_style: theme.font_bold{font_size: 16}
                        }
                    }
                    nyx_logo := Label{
                        text: "Nyx Operator"
                        draw_text.color: Cprimary
                        draw_text.text_style: theme.font_bold{font_size: 18}
                    }
                }
                connect_tagline := Label{
                    text: "Connect to a team server"
                    draw_text.color: Cmuted
                    draw_text.text_style: theme.font_regular{font_size: 12}
                }
            }
            View{width: Fill height: 1 draw_bg.color: Cborder}
            // Form body. See the module docs for the blend/border rationale.
            fields_view := View{
                width: Fill height: Fit
                padding: Inset{top: 6.0 bottom: 2.0 left: 20.0 right: 20.0}
                flow: Down spacing: 2.0

                // Server URL — host + port merged into one field.
                View{
                    width: Fill height: Fit flow: Down spacing: 1.0
                    url_label := Label{text: "Server URL *" draw_text.color: Csecond draw_text.text_style: theme.font_bold{font_size: 11}}
                    url_input := TextInput{
                        width: Fill height: 32
                        label_align: Align{y: 0.5}
                        padding: Inset{left: 12.0, right: 12.0, top: 4.0, bottom: 4.0}
                        text: "http://127.0.0.1:8443"
                        empty_text: "http://host:port"
                        draw_bg.color: Cinput
                        draw_bg.color_hover: Cinput
                        draw_bg.color_focus: Cinput
                        draw_bg.color_empty: Cinput
                        draw_bg.border_color: Cinput_b
                        draw_bg.border_color_hover: Cinput_b
                        draw_bg.border_color_focus: Caccent
                        draw_bg.border_color_empty: Cinput_b
                        draw_bg.border_color_2: Cinput_b
                        draw_bg.border_color_2_hover: Cinput_b
                        draw_bg.border_color_2_focus: Caccent
                        draw_bg.border_color_2_empty: Cinput_b
                        draw_bg.border_size: 1.0
                        draw_bg.border_radius: Cradius
                        draw_text.color: Cprimary
                        draw_text.color_hover: Cprimary
                        draw_text.color_focus: Cprimary
                        draw_text.color_empty: Cmuted
                        draw_text.text_style: theme.font_code{font_size: 13}
                        draw_cursor.color: Caccent
                    }
                    url_error := Label{
                        visible: false
                        text: ""
                        draw_text.color: Cdanger
                        draw_text.text_style: theme.font_code{font_size: 10}
                    }
                }
                View{
                    width: Fill height: Fit flow: Down spacing: 1.0
                    alias_label := Label{text: "Operator *" draw_text.color: Csecond draw_text.text_style: theme.font_bold{font_size: 11}}
                    alias_input := TextInput{
                        width: Fill height: 32
                        label_align: Align{y: 0.5}
                        padding: Inset{left: 12.0, right: 12.0, top: 4.0, bottom: 4.0}
                        text: "operator"
                        empty_text: "operator alias"
                        draw_bg.color: Cinput
                        draw_bg.color_hover: Cinput
                        draw_bg.color_focus: Cinput
                        draw_bg.color_empty: Cinput
                        draw_bg.border_color: Cinput_b
                        draw_bg.border_color_hover: Cinput_b
                        draw_bg.border_color_focus: Caccent
                        draw_bg.border_color_empty: Cinput_b
                        draw_bg.border_color_2: Cinput_b
                        draw_bg.border_color_2_hover: Cinput_b
                        draw_bg.border_color_2_focus: Caccent
                        draw_bg.border_color_2_empty: Cinput_b
                        draw_bg.border_size: 1.0
                        draw_bg.border_radius: Cradius
                        draw_text.color: Cprimary
                        draw_text.color_hover: Cprimary
                        draw_text.color_focus: Cprimary
                        draw_text.color_empty: Cmuted
                        draw_text.text_style: theme.font_code{font_size: 13}
                        draw_cursor.color: Caccent
                    }
                    alias_error := Label{
                        visible: false
                        text: ""
                        draw_text.color: Cdanger
                        draw_text.text_style: theme.font_code{font_size: 10}
                    }
                }
                View{
                    width: Fill height: Fit flow: Down spacing: 1.0
                    pass_label := Label{text: "Password (API Token) *" draw_text.color: Csecond draw_text.text_style: theme.font_bold{font_size: 11}}
                    pass_input := TextInput{
                        is_password: true
                        width: Fill height: 32
                        label_align: Align{y: 0.5}
                        padding: Inset{left: 12.0, right: 12.0, top: 4.0, bottom: 4.0}
                        text: ""
                        empty_text: "Enter Team Server Token"
                        draw_bg.color: Cinput
                        draw_bg.color_hover: Cinput
                        draw_bg.color_focus: Cinput
                        draw_bg.color_empty: Cinput
                        draw_bg.border_color: Cinput_b
                        draw_bg.border_color_hover: Cinput_b
                        draw_bg.border_color_focus: Caccent
                        draw_bg.border_color_empty: Cinput_b
                        draw_bg.border_color_2: Cinput_b
                        draw_bg.border_color_2_hover: Cinput_b
                        draw_bg.border_color_2_focus: Caccent
                        draw_bg.border_color_2_empty: Cinput_b
                        draw_bg.border_size: 1.0
                        draw_bg.border_radius: Cradius
                        draw_text.color: Cprimary
                        draw_text.color_hover: Cprimary
                        draw_text.color_focus: Cprimary
                        draw_text.color_empty: Cmuted
                        draw_text.text_style: theme.font_code{font_size: 13}
                        draw_cursor.color: Caccent
                    }
                    pass_helper := Label{
                        text: "Leave empty if none"
                        draw_text.color: Csecond
                        draw_text.text_style: theme.font_regular{font_size: 11}
                    }
                }
                connect_status := Label{
                    visible: false
                    text: ""
                    draw_text.color: Cdanger
                    draw_text.text_style: theme.font_code{font_size: 11}
                }
            }
            View{width: Fill height: 1 draw_bg.color: Cborder}
            View{
                width: Fill height: Fit
                padding: Inset{top: 10.0 bottom: 16.0 left: 20.0 right: 20.0}
                flow: Down spacing: 5.0
                theme_toggle_dialog := View {
                    width: Fill height: 32
                    flow: Right spacing: 0
                    padding: Inset{top: 0 bottom: 0 left: 0 right: 0}

                    // Secondary style: transparent fill, hairline
                    // border, muted text — never competes with
                    // the primary Connect button.
                    dialog_btn_theme := Button {
                        text: "THEME: DARK"
                        width: Fill height: Fill
                        draw_bg.color: #x00000000
                        draw_bg.color_hover: Crowhov
                        draw_bg.border_radius: Cradius
                        draw_bg.border_color: Cborder
                        draw_bg.border_size: 1.0
                        draw_text.color: Cmuted
                        draw_text.text_style: theme.font_code{font_size: 11}
                    }
                }
                dialog_connect_btn := Button{
                    text: "Connect"
                    width: Fill height: 36
                    draw_bg.color: Caccent
                    draw_bg.color_hover: Cacchov
                    draw_bg.border_radius: Cradius
                    draw_text.color: Conaccent
                    draw_text.text_style: theme.font_bold{font_size: 13}
                }
                connect_footer := Label{
                    text: "Authorized use only · all activity is logged"
                    draw_text.color: Cmuted
                    draw_text.text_style: theme.font_regular{font_size: 11}
                }
            }
        }
    }

    // ── connect overlay (masks the 420→1280 resize snap) ────────────────────
    // Shown by apply_snapshot right before the resize, hidden once the attempt
    // resolves. Opaque so the snap is invisible. Sibling of connect_view /
    // main_view (direct child of body +:) so it renders above both.
    mod.nyx.ConnectOverlay = SolidView{
        width: Fill height: Fill
        visible: false
        flow: Down
        align: Align{x: 0.5, y: 0.5}
        spacing: 14.0
        draw_bg.color: Cbg

        connect_title := Label {
            text: "[ ESTABLISHING LINK ]"
            draw_text.color: Csecond
            draw_text.text_style: theme.font_code{font_size: 11}
        }

        connect_progress := ConnectProgress {
            width: 240 height: 6
        }

        connect_step_tip := Label {
            text: ""
            draw_text.color: Csecond
            draw_text.text_style: theme.font_code{font_size: 11}
        }
    }
}

/// Map a connect stage to the operator-facing step-tip copy shown under the
/// progress bar. Empty when idle (overlay hidden anyway).
pub fn connect_stage_text(s: &bridge::ConnectStage) -> &'static str {
    use bridge::ConnectStage::*;
    match s {
        Idle => "",
        Resolving => "resolving host…",
        Connecting => "opening connection…",
        Authenticating => "awaiting session list…",
        Done => "connected",
        Failed => "connection failed",
    }
}

/// A dialog form field that can carry an inline error. Used by
/// [`set_field_error`] to route validation/backend errors to the right
/// `*_error` label without scattering raw `ids!()` paths around.
#[derive(Clone, Copy)]
pub enum Field {
    Url,
    Alias,
}

/// Which dialog field an inline error belongs to. Used by [`set_field_error`]
/// and [`validate_form`] so the routing logic and the rendering both name
/// fields symbolically.
pub fn set_field_error(ui: &WidgetRef, cx: &mut Cx, field: Field, msg: &str) {
    let path = match field {
        Field::Url => ids!(url_error),
        Field::Alias => ids!(alias_error),
    };
    let has_msg = !msg.is_empty();
    ui.label(cx, path).set_text(cx, msg);
    ui.view(cx, path).set_visible(cx, has_msg);
}

/// Client-side gate run before sending `Cmd::Connect`. Returns true iff the
/// form is valid; otherwise writes an inline message under the offending
/// field and leaves the connect attempt unstarted. Backend errors (refused,
/// auth) are handled separately by [`route_backend_error`].
///
/// Rules:
/// * URL must look like `http(s)://host:port` — scheme, host, and a 2–5
///   digit port. Path/query are allowed but ignored. Intentionally a sanity
///   check, not an RFC 3986 parse: it catches fat-finger mistakes without
///   dragging in a URL crate or rejecting exotic-but-valid hosts.
/// * Operator must be non-empty (it becomes the operator identity).
/// * Password is optional (local dev server without NYX_TOKEN).
pub fn validate_form(ui: &WidgetRef, cx: &mut Cx) -> bool {
    let url = ui.text_input(cx, ids!(url_input)).text();
    let alias = ui.text_input(cx, ids!(alias_input)).text();

    let url_ok = {
        // Anchored regex via the `regex`-style manual scan would need a
        // dependency; a hand-rolled check is enough for a login gate.
        let u = url.trim();
        let scheme_ok = u.starts_with("http://") || u.starts_with("https://");
        let rest = u.split_once("://").map(|(_, r)| r).unwrap_or("");
        // host (non-empty, no slash/colon before the port) + :port(2-5)
        let host_port = rest.split('/').next().unwrap_or("");
        let (host, port) = host_port
            .rsplit_once(':')
            .map(|(h, p)| (h, Some(p)))
            .unwrap_or((host_port, None));
        let host_ok = !host.is_empty() && !host.contains(' ') && host.chars().any(|c| c != '.');
        let port_ok = port
            .map(|p| p.len() >= 2 && p.len() <= 5 && p.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(false);
        scheme_ok && host_ok && port_ok
    };

    let alias_ok = !alias.trim().is_empty();

    // Always re-set both so a corrected field clears its old error.
    set_field_error(
        ui,
        cx,
        Field::Url,
        if url_ok {
            ""
        } else {
            "Enter a valid http(s)://host:port URL"
        },
    );
    set_field_error(
        ui,
        cx,
        Field::Alias,
        if alias_ok {
            ""
        } else {
            "Operator name is required"
        },
    );

    url_ok && alias_ok
}

/// Route a backend error line (the most recent one from the bridge log) to
/// the field it most likely came from, so the failure reads as "this field"
/// instead of a bottom-of-form blob. The bridge prefixes worker errors with
/// "! " (e.g. "! sessions: error sending request..."); reqwest embeds the
/// cause (connection refused / dns / status code) in the message text, so
/// substring matching is reliable here.
pub fn route_backend_error(ui: &WidgetRef, cx: &mut Cx, e: &str) {
    let lower = e.to_lowercase();
    if lower.contains("connection refused")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("dns")
        || lower.contains("unreachable")
        || lower.contains("connect error")
        || lower.contains("error connecting")
    {
        set_field_error(ui, cx, Field::Url, "Could not reach server at this address");
        set_field_error(ui, cx, Field::Alias, "");
        ui.label(cx, ids!(connect_status)).set_text(cx, "");
        ui.view(cx, ids!(connect_status)).set_visible(cx, false);
    } else if lower.contains("401")
        || lower.contains("403")
        || lower.contains("unauthorized")
        || lower.contains("forbidden")
        || lower.contains("invalid token")
    {
        // No dedicated pass_error label — surface auth failures on the
        // password field's column via the status line, since the helper text
        // already occupies the slot right below it.
        set_field_error(ui, cx, Field::Url, "");
        set_field_error(ui, cx, Field::Alias, "");
        ui.label(cx, ids!(connect_status))
            .set_text(cx, "Authentication failed — check your API token");
        ui.view(cx, ids!(connect_status)).set_visible(cx, true);
    } else {
        // Unattributable (e.g. 500, malformed response): keep the full text
        // on the fallback status line so nothing is lost.
        ui.label(cx, ids!(connect_status)).set_text(cx, e);
        ui.view(cx, ids!(connect_status))
            .set_visible(cx, !e.is_empty());
    }
}
