//! Keyboard capture and release for an embedded remote desktop.

use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use iced::advanced::{Layout, Shell, Widget, layout, mouse, renderer, widget};
use iced::{Element, Event, Length, Rectangle, Size, Vector, keyboard};
use uuid::Uuid;

use crate::{Message, protocol::RemoteInput};

pub(crate) struct DesktopInput<'a> {
    child: Element<'a, Message>,
    profile: Uuid,
    enabled: bool,
    id: widget::Id,
    capture_lease: Option<Arc<AtomicBool>>,
    clipboard_generation: Option<u64>,
}

#[derive(Default)]
struct State {
    profile: Uuid,
    focused: bool,
    inactive_window: bool,
    held: HashMap<keyboard::key::Physical, u32>,
    capture_lease: Option<Arc<AtomicBool>>,
}

impl State {
    fn paste_shortcut(
        &self,
        key: &keyboard::Key,
        physical: &keyboard::key::Physical,
        modifiers: keyboard::Modifiers,
    ) -> Option<bool> {
        use xkeysym::key as X;
        let held = |keys: &[u32]| self.held.values().any(|key| keys.contains(key));
        let control = modifiers.control() || held(&[X::Control_L, X::Control_R]);
        let blocked = modifiers.alt()
            || modifiers.logo()
            || held(&[
                X::Alt_L,
                X::Alt_R,
                X::ISO_Level3_Shift,
                X::Super_L,
                X::Super_R,
                X::Meta_L,
                X::Meta_R,
            ]);
        let paste_key = matches!(key, keyboard::Key::Character(c) if c.eq_ignore_ascii_case("v"))
            || *physical == keyboard::key::Physical::Code(keyboard::key::Code::KeyV);
        (control && !blocked && paste_key)
            .then(|| modifiers.shift() || held(&[X::Shift_L, X::Shift_R]))
    }
}

impl Drop for State {
    fn drop(&mut self) {
        if let Some(lease) = &self.capture_lease {
            lease.store(false, Ordering::SeqCst);
        }
    }
}

impl widget::operation::Focusable for State {
    fn is_focused(&self) -> bool {
        self.focused
    }
    fn focus(&mut self) {
        self.focused = true;
        if let Some(lease) = &self.capture_lease {
            lease.store(!self.inactive_window, Ordering::SeqCst);
        }
    }
    fn unfocus(&mut self) {
        self.focused = false;
        if let Some(lease) = &self.capture_lease {
            lease.store(false, Ordering::SeqCst);
        }
    }
}

impl<'a> DesktopInput<'a> {
    pub(crate) fn new(child: Element<'a, Message>, profile: Uuid, enabled: bool) -> Self {
        Self {
            child,
            profile,
            enabled,
            id: widget::Id::from(format!("remote-desktop-input-{profile}")),
            capture_lease: None,
            clipboard_generation: None,
        }
    }
    pub(crate) fn clipboard_generation(mut self, generation: Option<u64>) -> Self {
        self.clipboard_generation = generation;
        self
    }

    pub(crate) fn capture_lease(mut self, lease: Option<Arc<AtomicBool>>) -> Self {
        self.capture_lease = lease;
        self
    }
}

impl Widget<Message, iced::Theme, iced::Renderer> for DesktopInput<'_> {
    fn tag(&self) -> widget::tree::Tag {
        widget::tree::Tag::of::<State>()
    }
    fn state(&self) -> widget::tree::State {
        widget::tree::State::new(State {
            capture_lease: self.capture_lease.clone(),
            profile: self.profile,
            focused: false,
            inactive_window: false,
            held: HashMap::new(),
        })
    }
    fn diff(&mut self, tree: &mut widget::Tree) {
        let state = tree.state.downcast_mut::<State>();
        let same = match (&state.capture_lease, &self.capture_lease) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        if !same || state.profile != self.profile || !self.enabled {
            if let Some(lease) = &state.capture_lease {
                lease.store(false, Ordering::SeqCst);
            }
            state.focused = false;
            state.held.clear();
        }
        state.profile = self.profile;
        state.capture_lease = self.capture_lease.clone();
        tree.diff_children(std::slice::from_mut(&mut self.child));
    }
    fn size(&self) -> Size<Length> {
        self.child.as_widget().size()
    }
    fn layout(
        &mut self,
        tree: &mut widget::Tree,
        renderer: &iced::Renderer,
        limits: &layout::Limits,
    ) {
        use iced::advanced::layout::Measure;
        let child = self
            .child
            .as_widget_mut()
            .measure(&mut tree.children[0], renderer, limits);
        layout::Node::with_children(child.size(), vec![child]).apply(tree);
    }
    fn draw(
        &self,
        tree: &widget::Tree,
        renderer: &mut iced::Renderer,
        theme: &iced::Theme,
        style: &renderer::Style,
        layout: Layout,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
    ) {
        // Partial UI draws skip image-cache eviction until enzUI-ICED #3699 is fixed.
        if let iced_renderer::fallback::Renderer::Primary(renderer) = renderer {
            renderer.track_frame_damage(false);
        }
        let content_layout = child_layout(layout, tree);
        self.child.as_widget().draw(
            &tree.children[0],
            renderer,
            theme,
            style,
            content_layout,
            cursor,
            viewport,
        );
    }
    fn operate(
        &mut self,
        tree: &mut widget::Tree,
        layout: Layout,
        viewport: &Rectangle,
        renderer: &iced::Renderer,
        operation: &mut dyn widget::Operation,
    ) {
        if self.enabled {
            operation.focusable(
                Some(&self.id),
                layout.bounds(),
                tree.state.downcast_mut::<State>(),
            );
        }
        if self.enabled {
            use enzui_iced_core::collect::SemanticsNode;
            use enzui_iced_core::semantics::{Role, Semantics};
            let mut node = SemanticsNode::group(
                Semantics::new(Role::Group)
                    .label(crate::l10n::text("remote-desktop-input"))
                    .focusable()
                    .focused(tree.state.downcast_ref::<State>().focused),
            );
            operation.custom(Some(&self.id), layout.bounds(), &mut node);
            operation.container(Some(&self.id), layout.bounds(), viewport);
        }
        let content_layout = child_layout(layout, tree);
        self.child.as_widget_mut().operate(
            &mut tree.children[0],
            content_layout,
            viewport,
            renderer,
            operation,
        );
    }
    fn update(
        &mut self,
        tree: &mut widget::Tree,
        event: &Event,
        layout: Layout,
        cursor: mouse::Cursor,
        renderer: &iced::Renderer,
        shell: &mut Shell<'_, Message>,
        viewport: &Rectangle,
    ) {
        let state = tree.state.downcast_mut::<State>();
        let was_focused = state.focused;
        let release_chord = matches!(event, Event::Keyboard(keyboard::Event::KeyPressed { key: keyboard::Key::Named(keyboard::key::Named::Escape), modifiers, .. }) if modifiers.control() && modifiers.alt() && modifiers.shift());
        let pointer_press = matches!(event, Event::Mouse(mouse::Event::ButtonPressed(_)));
        let inside = cursor.is_over(layout.bounds());
        let loses_focus = !self.enabled || release_chord || (pointer_press && !inside);
        match event {
            Event::Window(iced::window::Event::Unfocused) => {
                state.inactive_window = true;
                shell.publish(Message::DesktopPointerCancel(self.profile));
            }
            Event::Window(iced::window::Event::Focused) => state.inactive_window = false,
            _ => {}
        }
        if loses_focus || !state.focused || state.inactive_window {
            for (_, keysym) in state.held.drain() {
                shell.publish(Message::DesktopKey(
                    self.profile,
                    RemoteInput::KeyUp(keysym),
                ));
            }
        }
        if loses_focus {
            state.focused = false;
        }
        if pointer_press && inside && self.enabled {
            state.focused = true;
        }
        if let Some(lease) = &state.capture_lease {
            lease.store(
                state.focused && self.enabled && !state.inactive_window,
                Ordering::SeqCst,
            );
        }
        if let Some(generation) = self.clipboard_generation
            && self.enabled
            && state.focused
            && !state.inactive_window
            && (!was_focused || matches!(event, Event::Window(iced::window::Event::Focused)))
        {
            shell.publish(Message::SyncClipboard(self.profile, generation, None));
        }
        if was_focused != state.focused {
            shell.request_redraw();
        }
        if release_chord && self.enabled {
            shell.capture_event();
            return;
        }
        if self.enabled
            && let Event::Mouse(mouse::Event::ButtonReleased(button)) = event
        {
            let button = match button {
                mouse::Button::Left => Some(crate::protocol::PointerButton::Left),
                mouse::Button::Middle => Some(crate::protocol::PointerButton::Middle),
                mouse::Button::Right => Some(crate::protocol::PointerButton::Right),
                _ => None,
            };
            if let Some(button) = button {
                shell.publish(Message::SessionPointer(
                    self.profile,
                    crate::session::PointerGesture::Released(button),
                ));
            }
        }
        if state.focused && self.enabled && !state.inactive_window {
            match event {
                Event::Keyboard(keyboard::Event::KeyPressed {
                    key,
                    modified_key,
                    physical_key,
                    location,
                    modifiers,
                    ..
                }) => {
                    if let Some(generation) = self.clipboard_generation
                        && let Some(shifted) = state.paste_shortcut(key, physical_key, *modifiers)
                    {
                        shell.publish(Message::SyncClipboard(
                            self.profile,
                            generation,
                            Some(shifted),
                        ));
                        shell.capture_event();
                        return;
                    }
                    if let Some(keysym) = keysym(modified_key, *location) {
                        let keysym = *state.held.entry(*physical_key).or_insert(keysym);
                        shell.publish(Message::DesktopKey(
                            self.profile,
                            RemoteInput::KeyDown(keysym),
                        ));
                        shell.capture_event();
                        return;
                    }
                }
                Event::Keyboard(keyboard::Event::KeyReleased { physical_key, .. }) => {
                    if let Some(keysym) = state.held.remove(physical_key) {
                        shell.publish(Message::DesktopKey(
                            self.profile,
                            RemoteInput::KeyUp(keysym),
                        ));
                        shell.capture_event();
                        return;
                    }
                }
                _ => {}
            }
        }
        let content_layout = child_layout(layout, tree);
        self.child.as_widget_mut().update(
            &mut tree.children[0],
            event,
            content_layout,
            cursor,
            renderer,
            shell,
            viewport,
        );
    }
    fn mouse_interaction(
        &self,
        tree: &widget::Tree,
        layout: Layout,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
        renderer: &iced::Renderer,
    ) -> mouse::Interaction {
        let content_layout = child_layout(layout, tree);
        self.child.as_widget().mouse_interaction(
            &tree.children[0],
            content_layout,
            cursor,
            viewport,
            renderer,
        )
    }
    fn overlay<'b>(
        &'b mut self,
        tree: &'b mut widget::Tree,
        layout: Layout,
        renderer: &iced::Renderer,
        viewport: &Rectangle,
        translation: Vector,
        window: Size,
    ) -> Vec<iced::advanced::overlay::Element<'b, Message, iced::Theme, iced::Renderer>> {
        let content_layout = child_layout(layout, tree);
        self.child.as_widget_mut().overlay(
            &mut tree.children[0],
            content_layout,
            renderer,
            viewport,
            translation,
            window,
        )
    }
}

fn child_layout(layout: Layout, tree: &widget::Tree) -> Layout {
    layout
        .children(&tree.children)
        .next()
        .expect("desktop input has one child")
}

pub(crate) fn keysym(key: &keyboard::Key, location: keyboard::Location) -> Option<u32> {
    use keyboard::key::Named as N;
    use xkeysym::key as X;
    let right = location == keyboard::Location::Right;
    Some(match key {
        keyboard::Key::Character(text) => xkeysym::Keysym::from_char(text.chars().next()?).raw(),
        keyboard::Key::Named(named) => match named {
            N::Enter => X::Return,
            N::Tab => X::Tab,
            N::Space => X::space,
            N::Backspace => X::BackSpace,
            N::Delete => X::Delete,
            N::Insert => X::Insert,
            N::Escape => X::Escape,
            N::Home => X::Home,
            N::End => X::End,
            N::PageUp => X::Page_Up,
            N::PageDown => X::Page_Down,
            N::ArrowUp => X::Up,
            N::ArrowDown => X::Down,
            N::ArrowLeft => X::Left,
            N::ArrowRight => X::Right,
            N::Shift => {
                if right {
                    X::Shift_R
                } else {
                    X::Shift_L
                }
            }
            N::Control => {
                if right {
                    X::Control_R
                } else {
                    X::Control_L
                }
            }
            N::Alt => {
                if right {
                    X::Alt_R
                } else {
                    X::Alt_L
                }
            }
            N::Super | N::Meta => {
                if right {
                    X::Super_R
                } else {
                    X::Super_L
                }
            }
            N::AltGraph => X::ISO_Level3_Shift,
            N::CapsLock => X::Caps_Lock,
            N::NumLock => X::Num_Lock,
            N::ScrollLock => X::Scroll_Lock,
            N::PrintScreen => X::Print,
            N::Pause => X::Pause,
            N::ContextMenu => X::Menu,
            N::F1 => X::F1,
            N::F2 => X::F2,
            N::F3 => X::F3,
            N::F4 => X::F4,
            N::F5 => X::F5,
            N::F6 => X::F6,
            N::F7 => X::F7,
            N::F8 => X::F8,
            N::F9 => X::F9,
            N::F10 => X::F10,
            N::F11 => X::F11,
            N::F12 => X::F12,
            N::F13 => X::F13,
            N::F14 => X::F14,
            N::F15 => X::F15,
            N::F16 => X::F16,
            N::F17 => X::F17,
            N::F18 => X::F18,
            N::F19 => X::F19,
            N::F20 => X::F20,
            N::F21 => X::F21,
            N::F22 => X::F22,
            N::F23 => X::F23,
            N::F24 => X::F24,
            _ => return None,
        },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use widget::operation::Focusable;

    #[test]
    fn inactive_or_retired_focus_cannot_keep_controller_capture() {
        let lease = Arc::new(AtomicBool::new(false));
        let mut state = State {
            capture_lease: Some(Arc::clone(&lease)),
            profile: Uuid::nil(),
            focused: false,
            inactive_window: false,
            held: HashMap::new(),
        };
        state.focus();
        assert!(lease.load(Ordering::SeqCst));
        state.unfocus();
        assert!(!lease.load(Ordering::SeqCst));
        state.inactive_window = true;
        state.focus();
        assert!(!lease.load(Ordering::SeqCst));
        state.inactive_window = false;
        state.focus();
        drop(state);
        assert!(!lease.load(Ordering::SeqCst));
    }
    #[test]
    fn paste_uses_held_modifiers_when_virtual_keyboard_flags_lag_and_excludes_alt_graph() {
        use keyboard::key::{Code, Physical};
        let mut state = State::default();
        state
            .held
            .insert(Physical::Code(Code::ControlLeft), xkeysym::key::Control_L);
        state
            .held
            .insert(Physical::Code(Code::ShiftLeft), xkeysym::key::Shift_L);
        let key = keyboard::Key::Character("v".into());
        let physical = Physical::Code(Code::KeyV);
        assert_eq!(
            state.paste_shortcut(&key, &physical, keyboard::Modifiers::empty()),
            Some(true)
        );
        state.held.insert(
            Physical::Code(Code::AltRight),
            xkeysym::key::ISO_Level3_Shift,
        );
        assert_eq!(
            state.paste_shortcut(&key, &physical, keyboard::Modifiers::empty()),
            None
        );
        state.held.clear();
        assert_eq!(
            state.paste_shortcut(&key, &physical, keyboard::Modifiers::empty()),
            None
        );
    }
}
