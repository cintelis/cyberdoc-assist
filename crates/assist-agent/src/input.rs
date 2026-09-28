//! Applies remote input to the local machine — but only while control is
//! granted (see [`Injector::set_allowed`]). Coordinates arrive normalised to
//! `0.0..=1.0` of the shared screen and are scaled to the monitor here.
//!
//! Every path that touches the OS runs through `enigo`; this crate itself
//! stays free of `unsafe`.

use anyhow::Result;
use assist_proto::{Control, MouseButton};
use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};

pub struct Injector {
    enigo: Enigo,
    width: i32,
    height: i32,
    allowed: bool,
}

impl Injector {
    pub fn new(width: u32, height: u32) -> Result<Self> {
        let enigo = Enigo::new(&Settings::default())?;
        Ok(Self {
            enigo,
            width: width as i32,
            height: height as i32,
            allowed: false,
        })
    }

    /// Turns input on or off. While `false`, [`apply`](Self::apply) drops every
    /// pointer and keyboard event — the switch the on-screen consent controls.
    pub fn set_allowed(&mut self, allowed: bool) {
        self.allowed = allowed;
    }

    fn to_pixels(&self, x: f64, y: f64) -> (i32, i32) {
        let clamp = |v: f64| v.clamp(0.0, 1.0);
        (
            (clamp(x) * self.width as f64) as i32,
            (clamp(y) * self.height as f64) as i32,
        )
    }

    /// Applies one control event. A no-op (returning `Ok`) when control is not
    /// granted, so a stray or replayed message can never move the mouse.
    pub fn apply(&mut self, event: &Control) -> Result<()> {
        if !self.allowed {
            return Ok(());
        }
        match event {
            Control::MouseMove { x, y } => {
                let (px, py) = self.to_pixels(*x, *y);
                self.enigo.move_mouse(px, py, Coordinate::Abs)?;
            }
            Control::MouseButton { button, down, x, y } => {
                let (px, py) = self.to_pixels(*x, *y);
                self.enigo.move_mouse(px, py, Coordinate::Abs)?;
                let dir = if *down {
                    Direction::Press
                } else {
                    Direction::Release
                };
                self.enigo.button(map_button(*button), dir)?;
            }
            Control::Wheel { dx, dy } => {
                // Browser deltas are pixels; coarse-quantise to wheel notches.
                let steps = |d: f64| (d / 100.0).round() as i32;
                let (sx, sy) = (steps(*dx), steps(*dy));
                if sy != 0 {
                    self.enigo.scroll(sy, Axis::Vertical)?;
                }
                if sx != 0 {
                    self.enigo.scroll(sx, Axis::Horizontal)?;
                }
            }
            Control::Key { key, down } => {
                let dir = if *down {
                    Direction::Press
                } else {
                    Direction::Release
                };
                self.enigo.key(map_key(key), dir)?;
            }
            // Control-flow messages are handled by the caller, not injected.
            Control::RequestControl
            | Control::ControlGranted
            | Control::ControlDenied { .. }
            | Control::ControlRevoked => {}
        }
        Ok(())
    }
}

fn map_button(button: MouseButton) -> Button {
    match button {
        MouseButton::Left => Button::Left,
        MouseButton::Middle => Button::Middle,
        MouseButton::Right => Button::Right,
    }
}

/// Maps a DOM `KeyboardEvent.key` value to an `enigo` key. Single printable
/// characters become [`Key::Unicode`]; named keys are matched explicitly;
/// anything unknown is dropped.
fn map_key(key: &str) -> Key {
    match key {
        "Enter" => Key::Return,
        "Backspace" => Key::Backspace,
        "Tab" => Key::Tab,
        "Escape" | "Esc" => Key::Escape,
        "ArrowUp" => Key::UpArrow,
        "ArrowDown" => Key::DownArrow,
        "ArrowLeft" => Key::LeftArrow,
        "ArrowRight" => Key::RightArrow,
        "Delete" => Key::Delete,
        "Home" => Key::Home,
        "End" => Key::End,
        "PageUp" => Key::PageUp,
        "PageDown" => Key::PageDown,
        "Shift" => Key::Shift,
        "Control" => Key::Control,
        "Alt" => Key::Alt,
        "Meta" => Key::Meta,
        "CapsLock" => Key::CapsLock,
        " " | "Spacebar" => Key::Space,
        "F1" => Key::F1,
        other => {
            let mut chars = other.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => Key::Unicode(c),
                // Unknown named key: map to a harmless no-op character.
                _ => Key::Unicode('\0'),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_keys_map() {
        assert!(matches!(map_key("Enter"), Key::Return));
        assert!(matches!(map_key("a"), Key::Unicode('a')));
        assert!(matches!(map_key("ArrowUp"), Key::UpArrow));
    }
}
