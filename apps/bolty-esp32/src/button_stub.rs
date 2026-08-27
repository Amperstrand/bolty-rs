//! No-op button module for boards without physical buttons (e.g. M5Atom).
//! Wired in by `main.rs` when `board-m5stick` is off, so the shared console,
//! hwtest, and main-loop paths compile without per-site cfg attributes.
use crate::commands::ButtonMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonEvent {
    None,
    Click,
    LongPress,
}

pub struct ButtonHandler;

impl ButtonHandler {
    pub fn poll(&mut self, _now_ms: u64) -> (ButtonEvent, ButtonEvent) {
        (ButtonEvent::None, ButtonEvent::None)
    }
}

pub fn get_button_mode() -> ButtonMode {
    ButtonMode::Simple
}

pub fn set_button_mode(_mode: ButtonMode) {}
