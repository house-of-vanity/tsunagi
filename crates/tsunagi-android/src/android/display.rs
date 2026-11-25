//! Android owns the GLES surface, keyboard and clipboard. egui owns the widgets.
use crate::view::{Phone, SystemAction};
use egui::{
    Event, ImeEvent, Key, Modifiers, PointerButton, Pos2, TouchDeviceId, TouchId, TouchPhase,
};
use egui_glow::{Painter, glow};
use jni::{
    JNIEnv,
    objects::{JObject, JString, JValue},
    sys::{jboolean, jfloat, jint, jlong},
};
use std::{
    cell::RefCell,
    ffi::{c_char, c_void},
    sync::Arc,
    time::Instant,
};

#[link(name = "EGL")]
unsafe extern "C" {
    fn eglGetProcAddress(name: *const c_char) -> *const c_void;
}

struct Display {
    painter: Painter,
    ctx: egui::Context,
    ui: Phone,
    events: Vec<Event>,
    primary: Option<i32>,
    start: Instant,
    ime: i32,
    exit_active: bool,
}
thread_local! { static DISPLAY: RefCell<Option<Display>> = const {RefCell::new(None)}; }

fn with_display<T: Default>(f: impl FnOnce(&mut Display) -> T) -> T {
    DISPLAY.with_borrow_mut(|d| d.as_mut().map(f).unwrap_or_default())
}

#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_surface(mut env: JNIEnv, _: JObject) {
    // SAFETY: GLSurfaceView invokes this callback on the GL thread with its ES3 context current.
    let gl = unsafe {
        glow::Context::from_loader_function_cstr(|name| eglGetProcAddress(name.as_ptr()))
    };
    let Ok(painter) = Painter::new(Arc::new(gl), "", None, false) else {
        let _ = env.throw_new(
            "java/lang/IllegalStateException",
            "Could not initialise OpenGL ES",
        );
        return;
    };
    let ctx = egui::Context::default();
    crate::view::configure(&ctx);
    DISPLAY.with_borrow_mut(|d| {
        // If Android discarded the old EGL context, its GPU resources are already gone.
        let ui = d
            .take()
            .map(|old| {
                // A rotation can recreate EGL. Keep expanded peers and scroll positions
                // while the new context uploads its own font atlas.
                let data = old.ctx.data_mut(std::mem::take);
                ctx.data_mut(|current| *current = data);
                old.ui
            })
            .unwrap_or_default();
        *d = Some(Display {
            painter,
            ctx,
            ui,
            events: Vec::new(),
            primary: None,
            start: Instant::now(),
            ime: -1,
            exit_active: false,
        });
    });
}
#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_draw(
    mut env: JNIEnv,
    _: JObject,
    host: JObject,
    w: jint,
    h: jint,
    scale: jfloat,
    service_started: jboolean,
    landscape: jboolean,
) -> jlong {
    with_display(|d| {
        tsunagi_ui::widgets::set_landscape(&d.ctx, landscape != 0);
        let size = egui::vec2(w as f32, h as f32) / scale;
        let mut input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(Pos2::ZERO, size)),
            events: std::mem::take(&mut d.events),
            time: Some(d.start.elapsed().as_secs_f64()),
            ..Default::default()
        };
        if let Some(info) = input.viewports.get_mut(&egui::ViewportId::ROOT) {
            info.native_pixels_per_point = Some(scale);
        }
        let mut action = None;
        let state = match super::status() {
            crate::service::State::Off if service_started != 0 => crate::service::State::Starting,
            state => state,
        };
        let exit_active = matches!(&state, crate::service::State::Ready(report, _) if report.networks.iter().any(|n| n.active && n.exit.via.is_some()));
        if exit_active && !d.exit_active {
            let _ = env.call_method(&host, "requestExitNotifications", "()V", &[]);
        }
        d.exit_active = exit_active;
        let output = d.ctx.run(input, |ctx| {
            action = d.ui.draw(ctx, &state, super::send).or(action);
        });
        if let Some(action) = action {
            let method = match action {
                SystemAction::Start => "startAgent",
                SystemAction::Stop => "stopAgent",
                SystemAction::PasteSecret => "pasteSecret",
                SystemAction::Finish => "closeScreen",
            };
            let _ = env.call_method(&host, method, "()V", &[]);
        }
        if let Some(secret) = d.ui.take_copied_secret()
            && let Ok(text) = env.new_string(secret.as_str())
        {
            let _ = env.call_method(
                &host,
                "copySecret",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&text)],
            );
        }
        for command in output.platform_output.commands {
            let (method, value) = match command {
                egui::OutputCommand::CopyText(text) => ("copyText", text),
                egui::OutputCommand::OpenUrl(url) => ("openUrl", url.url),
                _ => continue,
            };
            if let Ok(text) = env.new_string(value) {
                let _ = env.call_method(
                    &host,
                    method,
                    "(Ljava/lang/String;)V",
                    &[JValue::Object(&text)],
                );
            }
        }
        let ime = if output.platform_output.ime.is_none() {
            0
        } else if d.ui.secret_focused(&d.ctx) {
            2
        } else {
            1
        };
        if ime != d.ime {
            d.ime = ime;
            let _ = env.call_method(&host, "keyboard", "(I)V", &[JValue::Int(ime)]);
        }
        let ppp = output.pixels_per_point;
        let primitives = d.ctx.tessellate(output.shapes, ppp);
        let pixels = [w as u32, h as u32];
        d.painter.clear(pixels, [0.1, 0.1, 0.1, 1.0]);
        d.painter
            .paint_and_update_textures(pixels, ppp, &primitives, &output.textures_delta);
        output
            .viewport_output
            .get(&egui::ViewportId::ROOT)
            .map_or(1000, |v| {
                v.repaint_delay.as_millis().clamp(16, 1000) as jlong
            })
    })
}
#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_touch(
    _: JNIEnv,
    _: JObject,
    action: jint,
    id: jint,
    x: jfloat,
    y: jfloat,
) {
    with_display(|d| {
        let pos = egui::pos2(x, y);
        let phase = match action {
            0 => TouchPhase::Start,
            1 => TouchPhase::Move,
            2 => TouchPhase::End,
            _ => TouchPhase::Cancel,
        };
        d.events.push(Event::Touch {
            device_id: TouchDeviceId(0),
            id: TouchId(id as u64),
            phase,
            pos,
            force: None,
        });
        if phase == TouchPhase::Start && d.primary.is_none() {
            d.primary = Some(id);
        }
        if d.primary != Some(id) {
            return;
        }
        if phase != TouchPhase::Cancel {
            d.events.push(Event::PointerMoved(pos));
        }
        if phase != TouchPhase::Move {
            if phase == TouchPhase::Cancel {
                d.events.push(Event::PointerGone);
            }
            d.events.push(Event::PointerButton {
                pos,
                button: PointerButton::Primary,
                pressed: phase == TouchPhase::Start,
                modifiers: Modifiers::NONE,
            });
        }
        if matches!(phase, TouchPhase::Cancel | TouchPhase::End) {
            d.events.push(Event::PointerGone);
            d.primary = None;
        }
    });
}
#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_input(
    mut env: JNIEnv,
    _: JObject,
    kind: jint,
    value: JString,
) {
    let Ok(text) = env.get_string(&value) else {
        return;
    };
    let text = String::from(text);
    with_display(|d| match kind {
        0 => d.events.push(Event::Text(text)),
        1 => d.events.push(Event::Ime(ImeEvent::Enabled)),
        2 => d.events.push(Event::Ime(ImeEvent::Preedit(text))),
        3 => {
            d.events.push(Event::Ime(ImeEvent::Commit(text)));
            d.events.push(Event::Ime(ImeEvent::Disabled));
        }
        4 => d.ui.paste_secret(text),
        5 => d.ui.error(text),
        6 => d.ui.request_exit_picker(),
        _ => {}
    });
}
#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_key(_: JNIEnv, _: JObject, key: jint) {
    let key = match key {
        67 => Key::Backspace,
        112 => Key::Delete,
        66 => Key::Enter,
        21 => Key::ArrowLeft,
        22 => Key::ArrowRight,
        61 => Key::Tab,
        _ => return,
    };
    with_display(|d| {
        for pressed in [true, false] {
            d.events.push(Event::Key {
                key,
                physical_key: None,
                pressed,
                repeat: false,
                modifiers: Modifiers::NONE,
            });
        }
    });
}
#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_back(mut env: JNIEnv, _: JObject, host: JObject) {
    with_display(|d| {
        if d.ui.back() == Some(SystemAction::Finish) {
            let _ = env.call_method(&host, "closeScreen", "()V", &[]);
        }
    });
}
