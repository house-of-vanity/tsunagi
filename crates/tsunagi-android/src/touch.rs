//! Translate Android fingers into egui touch events and one primary pointer.
use egui::{Event, Modifiers, PointerButton, Pos2, TouchDeviceId, TouchId, TouchPhase};

#[derive(Default)]
pub(crate) struct TouchInput {
    primary: Option<i32>,
    clear_after_release: bool,
}

impl TouchInput {
    pub(crate) fn push(&mut self, events: &mut Vec<Event>, phase: TouchPhase, id: i32, pos: Pos2) {
        events.push(Event::Touch {
            device_id: TouchDeviceId(0),
            id: TouchId(id as u64),
            phase,
            pos,
            force: None,
        });
        if phase == TouchPhase::Start && self.primary.is_none() {
            self.primary = Some(id);
            self.clear_after_release = false;
        }
        if self.primary != Some(id) {
            return;
        }
        if phase != TouchPhase::Cancel {
            events.push(Event::PointerMoved(pos));
        }
        if phase != TouchPhase::Move {
            events.push(Event::PointerButton {
                pos,
                button: PointerButton::Primary,
                pressed: phase == TouchPhase::Start,
                modifiers: Modifiers::NONE,
            });
        }
        match phase {
            TouchPhase::End => {
                self.primary = None;
                self.clear_after_release = true;
            }
            TouchPhase::Cancel => {
                self.primary = None;
                events.push(Event::PointerGone);
            }
            _ => {}
        }
    }

    pub(crate) fn take_frame(&mut self, events: &mut Vec<Event>) -> Vec<Event> {
        let frame = std::mem::take(events);
        // ScrollArea reads the release velocity in this frame. PointerGone clears
        // egui's position history, so clear the touch hover in the following frame.
        if std::mem::take(&mut self.clear_after_release) {
            events.push(Event::PointerGone);
        }
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::{CentralPanel, Context, RawInput, Rect, ScrollArea, pos2, vec2};

    #[test]
    fn a_flick_coasts_and_slows_while_a_cancelled_drag_stops() {
        for end in [TouchPhase::End, TouchPhase::Cancel] {
            let ctx = Context::default();
            ctx.set_os(egui::os::OperatingSystem::Android);
            let mut input = TouchInput::default();
            let mut events = Vec::new();
            let mut frame_no = 0;
            let mut frame = |touch| {
                if let Some((phase, y)) = touch {
                    input.push(&mut events, phase, 0, pos2(80., y));
                }
                frame_no += 1;
                let mut offset = 0.;
                let _ = ctx.run(
                    RawInput {
                        time: Some(f64::from(frame_no) / 60.),
                        events: input.take_frame(&mut events),
                        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(320., 320.))),
                        ..Default::default()
                    },
                    |ctx| {
                        CentralPanel::default().show(ctx, |ui| {
                            offset = ScrollArea::vertical()
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    for i in 0..60 {
                                        ui.add_sized(
                                            [270., 40.],
                                            egui::Button::new(format!("Peer {i}")),
                                        );
                                    }
                                })
                                .state
                                .offset
                                .y;
                        });
                    },
                );
                offset
            };
            // The first layout measures the content. The next registers its drag area.
            frame(None);
            frame(None);
            frame(Some((TouchPhase::Start, 220.)));
            for y in [208., 190., 168., 146.] {
                frame(Some((TouchPhase::Move, y)));
            }
            let released = frame(Some((end, 126.)));
            let first = frame(None);
            let second = frame(None);
            assert!(released > 0., "{end:?} should follow a drag");
            if end == TouchPhase::End {
                assert!(
                    second > first && first > released,
                    "the scroll should coast after release"
                );
                assert!(
                    second - first < first - released,
                    "the fling should decelerate"
                );
            } else {
                assert_eq!((released, first), (first, second));
            }
        }
    }

    #[test]
    fn a_new_primary_touch_supersedes_a_release_in_the_same_frame() {
        let mut input = TouchInput::default();
        let mut events = Vec::new();
        for (phase, id) in [
            (TouchPhase::Start, 1),
            (TouchPhase::End, 1),
            (TouchPhase::Start, 2),
        ] {
            input.push(&mut events, phase, id, Pos2::ZERO);
        }
        let frame = input.take_frame(&mut events);
        assert!(matches!(
            frame.last(),
            Some(Event::PointerButton { pressed: true, .. })
        ));
        assert!(events.is_empty());
        input.push(&mut events, TouchPhase::End, 2, Pos2::ZERO);
        let release = input.take_frame(&mut events);
        assert!(matches!(
            release.last(),
            Some(Event::PointerButton { pressed: false, .. })
        ));
        assert!(matches!(
            input.take_frame(&mut events).as_slice(),
            [Event::PointerGone]
        ));
    }
}
