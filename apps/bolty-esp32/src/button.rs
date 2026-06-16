use core::sync::atomic::{AtomicU8, Ordering};

use esp_idf_hal::gpio::{Gpio37, Gpio39, Input, PinDriver};

use crate::commands::ButtonMode;

const DEBOUNCE_TICKS: u8 = 2;
const LONG_PRESS_MS: u64 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonEvent {
    None,
    Click,
    LongPress,
}

struct ButtonDebounce {
    debounce_count: u8,
    debounced_pressed: bool,
    press_start_ms: u64,
    long_press_fired: bool,
}

impl ButtonDebounce {
    const fn new() -> Self {
        Self {
            debounce_count: 0,
            debounced_pressed: false,
            press_start_ms: 0,
            long_press_fired: false,
        }
    }

    fn update(&mut self, raw_pressed: bool, now_ms: u64) -> ButtonEvent {
        if raw_pressed {
            if !self.debounced_pressed {
                self.debounce_count = self.debounce_count.saturating_add(1);
                if self.debounce_count >= DEBOUNCE_TICKS {
                    self.debounced_pressed = true;
                    self.press_start_ms = now_ms;
                    self.long_press_fired = false;
                }
            } else if !self.long_press_fired
                && now_ms.saturating_sub(self.press_start_ms) >= LONG_PRESS_MS
            {
                self.long_press_fired = true;
                return ButtonEvent::LongPress;
            }
        } else {
            self.debounce_count = 0;
            if self.debounced_pressed {
                self.debounced_pressed = false;
                if !self.long_press_fired {
                    return ButtonEvent::Click;
                }
            }
        }
        ButtonEvent::None
    }
}

pub struct ButtonHandler {
    front: PinDriver<'static, Gpio37, Input>,
    side: PinDriver<'static, Gpio39, Input>,
    front_state: ButtonDebounce,
    side_state: ButtonDebounce,
}

impl ButtonHandler {
    pub fn new(
        front: PinDriver<'static, Gpio37, Input>,
        side: PinDriver<'static, Gpio39, Input>,
    ) -> Self {
        Self {
            front,
            side,
            front_state: ButtonDebounce::new(),
            side_state: ButtonDebounce::new(),
        }
    }

    pub fn poll(&mut self, now_ms: u64) -> (ButtonEvent, ButtonEvent) {
        let front_pressed = self.front.is_low();
        let side_pressed = self.side.is_low();

        let front_event = self.front_state.update(front_pressed, now_ms);
        let side_event = self.side_state.update(side_pressed, now_ms);

        (front_event, side_event)
    }
}

static BUTTON_MODE: AtomicU8 = AtomicU8::new(0);

pub fn get_button_mode() -> ButtonMode {
    match BUTTON_MODE.load(Ordering::SeqCst) {
        1 => ButtonMode::Legacy,
        _ => ButtonMode::Simple,
    }
}

pub fn set_button_mode(mode: ButtonMode) {
    let val = match mode {
        ButtonMode::Simple => 0,
        ButtonMode::Legacy => 1,
    };
    BUTTON_MODE.store(val, Ordering::SeqCst);
}
