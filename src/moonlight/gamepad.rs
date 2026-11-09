use std::collections::BTreeMap;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use moonlight_common::stream::{
    c::MoonlightStream,
    control::{ActiveGamepads, ControllerButtons, ControllerCapabilities, ControllerType},
};
use sdl2::controller::{Axis, Button, GameController};

use crate::protocol::ProtocolError;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct State {
    buttons: u32,
    left_trigger: u8,
    right_trigger: u8,
    sticks: [i16; 4],
}

impl State {
    fn read(controller: &GameController) -> Self {
        use ControllerButtons as C;
        let mut buttons = C::empty();
        for (button, flag) in [
            (Button::A, C::A),
            (Button::B, C::B),
            (Button::X, C::X),
            (Button::Y, C::Y),
            (Button::Back, C::BACK),
            (Button::Start, C::PLAY),
            (Button::Guide, C::SPECIAL),
            (Button::LeftStick, C::LS_CLK),
            (Button::RightStick, C::RS_CLK),
            (Button::LeftShoulder, C::LB),
            (Button::RightShoulder, C::RB),
            (Button::DPadUp, C::UP),
            (Button::DPadDown, C::DOWN),
            (Button::DPadLeft, C::LEFT),
            (Button::DPadRight, C::RIGHT),
            (Button::Misc1, C::MISC),
            (Button::Paddle1, C::PADDLE1),
            (Button::Paddle2, C::PADDLE2),
            (Button::Paddle3, C::PADDLE3),
            (Button::Paddle4, C::PADDLE4),
            (Button::Touchpad, C::TOUCHPAD),
        ] {
            if controller.button(button) {
                buttons |= flag;
            }
        }
        Self {
            buttons: buttons.bits(),
            left_trigger: trigger(controller.axis(Axis::TriggerLeft)),
            right_trigger: trigger(controller.axis(Axis::TriggerRight)),
            sticks: [
                controller.axis(Axis::LeftX),
                controller.axis(Axis::LeftY).saturating_neg(),
                controller.axis(Axis::RightX),
                controller.axis(Axis::RightY).saturating_neg(),
            ],
        }
    }
    fn send(
        self,
        stream: &MoonlightStream,
        slot: u8,
        mask: ActiveGamepads,
    ) -> Result<(), ProtocolError> {
        stream
            .send_multi_controller(
                slot,
                mask,
                ControllerButtons::from_bits_truncate(self.buttons),
                self.left_trigger,
                self.right_trigger,
                self.sticks[0],
                self.sticks[1],
                self.sticks[2],
                self.sticks[3],
            )
            .map_err(|_| error())
    }
}

fn trigger(value: i16) -> u8 {
    (u32::from(value.max(0) as u16) * 255 / 32767) as u8
}

struct Controller {
    device: GameController,
    slot: u8,
    last: Option<State>,
    announced: bool,
}

pub(super) struct Gamepads {
    _context: sdl2::Sdl,
    subsystem: sdl2::GameControllerSubsystem,
    events: sdl2::EventPump,
    controllers: BTreeMap<u32, Controller>,
    rumble: Receiver<(u16, u16, u16)>,
    captured: bool,
    next_scan: Instant,
}

fn error() -> ProtocolError {
    ProtocolError::Refused("Gamepad forwarding failed. Check controller permissions or disable gamepads in this connection's settings.".into())
}

impl Gamepads {
    pub(super) fn new(rumble: Receiver<(u16, u16, u16)>) -> Result<Self, ProtocolError> {
        // Iced owns the window; the remote capture lease gates forwarding instead of SDL focus.
        if !sdl2::hint::set("SDL_JOYSTICK_ALLOW_BACKGROUND_EVENTS", "1") {
            return Err(error());
        }
        let context = sdl2::init().map_err(|_| error())?;
        let subsystem = context.game_controller().map_err(|_| error())?;
        let events = context.event_pump().map_err(|_| error())?;
        Ok(Self {
            _context: context,
            subsystem,
            events,
            controllers: BTreeMap::new(),
            rumble,
            captured: false,
            next_scan: Instant::now(),
        })
    }

    pub(super) fn poll(
        &mut self,
        stream: &MoonlightStream,
        captured: bool,
    ) -> Result<(), ProtocolError> {
        self.subsystem.update();
        for _ in self.events.poll_iter().take(256) {}
        let detached: Vec<_> = self
            .controllers
            .iter()
            .filter(|(_, controller)| !controller.device.attached())
            .map(|(&id, _)| id)
            .collect();
        for id in detached {
            let Some(mut controller) = self.controllers.remove(&id) else {
                continue;
            };
            let mask = self.mask();
            if controller.announced {
                State::default().send(stream, controller.slot, mask)?;
            }
            let _ = controller.device.set_rumble(0, 0, 0);
        }
        let count = if Instant::now() >= self.next_scan {
            self.next_scan = Instant::now() + Duration::from_millis(500);
            self.subsystem.num_joysticks().map_err(|_| error())?
        } else {
            0
        };
        for index in 0..count.min(64) {
            if self.controllers.len() == 16 || !self.subsystem.is_game_controller(index) {
                continue;
            }
            let device = self.subsystem.open(index).map_err(|_| error())?;
            let id = device.instance_id();
            if self.controllers.contains_key(&id) {
                continue;
            }
            let Some(slot) = (0..16).find(|slot| {
                self.controllers
                    .values()
                    .all(|controller| controller.slot != *slot)
            }) else {
                break;
            };
            self.controllers.insert(
                id,
                Controller {
                    device,
                    slot,
                    last: None,
                    announced: false,
                },
            );
        }
        let mask = self.mask();
        for controller in self.controllers.values_mut() {
            if !captured {
                if controller.announced && self.captured {
                    State::default().send(stream, controller.slot, mask)?;
                    let _ = controller.device.set_rumble(0, 0, 0);
                }
                controller.last = None;
                continue;
            }
            if !controller.announced {
                let mut capabilities = ControllerCapabilities::ANALOG_TRIGGERS;
                if controller.device.has_rumble() {
                    capabilities |= ControllerCapabilities::RUMBLE;
                }
                stream
                    .send_controller_arrival(
                        controller.slot,
                        mask,
                        ControllerType::Unknown,
                        ControllerButtons::all(),
                        capabilities,
                    )
                    .map_err(|_| error())?;
                controller.announced = true;
            }
            let state = State::read(&controller.device);
            if controller.last != Some(state) {
                state.send(stream, controller.slot, mask)?;
                controller.last = Some(state);
            }
        }
        for _ in 0..32 {
            let Ok((slot, low, high)) = self.rumble.try_recv() else {
                break;
            };
            if captured
                && let Some(controller) = self
                    .controllers
                    .values_mut()
                    .find(|controller| u16::from(controller.slot) == slot)
            {
                let _ = controller.device.set_rumble(low, high, 200);
            }
        }
        self.captured = captured;
        Ok(())
    }

    fn mask(&self) -> ActiveGamepads {
        ActiveGamepads::from_bits_truncate(
            self.controllers
                .values()
                .fold(0, |mask, controller| mask | (1 << controller.slot)),
        )
    }

    pub(super) fn release(&mut self, stream: &MoonlightStream) {
        for controller in self.controllers.values_mut() {
            if controller.announced {
                let _ = State::default().send(stream, controller.slot, ActiveGamepads::empty());
            }
            let _ = controller.device.set_rumble(0, 0, 0);
        }
        self.captured = false;
    }
}

impl Drop for Gamepads {
    fn drop(&mut self) {
        for controller in self.controllers.values_mut() {
            let _ = controller.device.set_rumble(0, 0, 0);
        }
    }
}

#[cfg(test)]
mod tests {}
