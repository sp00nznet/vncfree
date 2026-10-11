//! vncfree - a free VNC (RFB) client for Windows.
//!
//! Live window, keyboard and mouse, shared clipboard, automatic reconnect. Speaks
//! RFB 3.8 with Raw, CopyRect and ZRLE encodings, and authenticates with either
//! classic VNC auth or Apple's Diffie-Hellman scheme for macOS.
//!
//! Run with no arguments and it asks where to connect. Given an address it connects
//! straight away, and a second argument is a path for a headless one-frame PPM dump.
//! Settings come from the environment: VNC_USERNAME, VNC_PASSWORD, VNC_VIEW_ONLY,
//! VNC_ENCODING, VNC_DEBUG, VNC_SCROLL_DIVISOR.

use std::collections::HashMap;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use minifb::{Key, KeyRepeat, MouseButton, MouseMode, ScaleMode, Window, WindowOptions};
use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::UI::WindowsAndMessaging::{SystemParametersInfoW, SPI_GETWORKAREA};

use vncfree::rfb::*;
use vncfree::{cut_text_msg, debug, Res, Screen};

/// Set once the connect dialog has been used, which means the program was almost
/// certainly launched by double-clicking and has no console to print to.
static FROM_GUI: AtomicBool = AtomicBool::new(false);

/// Returning Result from main would print errors with Debug, which escapes the
/// newlines in our multi-line hints into literal \n. Print them ourselves.
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        if FROM_GUI.load(Ordering::Relaxed) {
            vncfree::gui::alert("vncfree", &e.to_string());
        }
        std::process::exit(1);
    }
}

/// The connect dialog. The address starts empty on purpose: a plausible-looking
/// placeholder gets left in place and then spends twenty seconds timing out against a
/// host that does not exist. Empty keeps Connect greyed out until it is a real answer.
fn ask_where_to_connect() -> Res<Option<Target>> {
    let mut fields = vec![
        vncfree::gui::Field::new("Address", false, true),
        vncfree::gui::Field::new("Username", false, false),
        vncfree::gui::Field::new("Password", true, false),
    ];
    // Pre-fill from the environment if it is set, so the variable still works.
    fields[1].value = env::var("VNC_USERNAME").unwrap_or_default();
    let note = "Address is host:port, for example 192.168.1.50:5900.\n\
                Username is only for a Mac - leave it blank if not needed.";
    let check: vncfree::gui::Validator =
        |f| vncfree::gui::check_host_port("The address", &f[0].value);
    if !vncfree::gui::form(
        "vncfree - connect",
        note,
        &mut fields,
        "Connect",
        Some(check),
    ) {
        return Ok(None);
    }
    Ok(Some(Target {
        addr: fields[0].value.trim().to_string(),
        user: fields[1].value.trim().to_string(),
        pass: fields[2].value.clone(),
    }))
}

fn run() -> Res<()> {
    let args: Vec<String> = env::args().collect();
    // With no arguments, ask. Arguments and environment variables keep working
    // untouched so scripts and shortcuts do not suddenly pop up a window.
    let target = match args.get(1) {
        Some(addr) => Target {
            addr: addr.clone(),
            user: env::var("VNC_USERNAME").unwrap_or_default(),
            pass: env::var("VNC_PASSWORD").unwrap_or_default(),
        },
        None => {
            FROM_GUI.store(true, Ordering::Relaxed);
            match ask_where_to_connect()? {
                Some(t) => t,
                None => return Ok(()), // window closed
            }
        }
    };
    let writer: Writer = Arc::new(Mutex::new(None));
    let clip: Clip = Arc::new(Mutex::new(String::new()));
    let cursor = SharedCursor::default();
    let mut vnc = Vnc::connect(&target, writer, clip.clone(), cursor.clone())?;

    match args.get(2) {
        Some(out) => {
            vnc.request(false)?;
            while !vnc.pump()? {}
            write_ppm(out, &vnc.screen)?;
            println!("wrote {} ({}x{})", out, vnc.screen.w, vnc.screen.h);
            Ok(())
        }
        None => run_window(vnc, target, clip, cursor),
    }
}

// ---------------------------------------------------------------- input

/// Whether Windows will also deliver this key as a character.
///
/// minifb identifies keys by *scancode*, so `Key::Key2` is the key in that physical
/// position whatever is printed on it. Which character that produces is the keyboard
/// layout's business, and the table below only knows the US one - on a UK keyboard the
/// same key is `"` rather than `@`, and on a German one `@` is not reachable without
/// AltGr at all. Windows has already applied the layout, the dead keys and AltGr by the
/// time it sends `WM_CHAR`, so for anything that produces a character that is where the
/// keysym comes from, and this list says which keys those are.
fn types_a_character(k: Key) -> bool {
    use Key::*;
    let n = k as u32;
    (A as u32..=Z as u32).contains(&n)
        || (Key0 as u32..=Key9 as u32).contains(&n)
        // The numeric keypad sends characters too, when Num Lock is on.
        || (NumPad0 as u32..=NumPad9 as u32).contains(&n)
        || matches!(
            k,
            Apostrophe
                | Backquote
                | Backslash
                | Comma
                | Equal
                | LeftBracket
                | Minus
                | Period
                | RightBracket
                | Semicolon
                | Slash
                | Space
                | NumPadDot
                | NumPadSlash
                | NumPadAsterisk
                | NumPadMinus
                | NumPadPlus
        )
}

/// X11 keysym for a minifb key, honouring shift. Printable ASCII keysyms are just
/// the character's ASCII value; everything else comes from the 0xff00 block.
///
/// The printable half assumes a US layout and is used for two things: keys held with
/// Ctrl or Alt, where the shortcut matters more than the character, and typing the
/// clipboard. Ordinary typing goes via the character callback instead - see
/// `types_a_character` above.
fn keysym(k: Key, shift: bool) -> Option<u32> {
    use Key::*;
    let n = k as u32;
    // minifb lays these enum variants out contiguously - see the test below.
    if (A as u32..=Z as u32).contains(&n) {
        let off = (n - A as u32) as u8;
        return Some((if shift { b'A' } else { b'a' } + off) as u32);
    }
    if (Key0 as u32..=Key9 as u32).contains(&n) {
        let d = (n - Key0 as u32) as usize;
        return Some(if shift {
            b")!@#$%^&*("[d]
        } else {
            b'0' + d as u8
        } as u32);
    }
    if (F1 as u32..=F15 as u32).contains(&n) {
        return Some(0xffbe + (n - F1 as u32));
    }
    if (NumPad0 as u32..=NumPad9 as u32).contains(&n) {
        return Some(0xffb0 + (n - NumPad0 as u32));
    }
    Some(match k {
        Apostrophe => (if shift { '"' } else { '\'' }) as u32,
        Backquote => (if shift { '~' } else { '`' }) as u32,
        Backslash => (if shift { '|' } else { '\\' }) as u32,
        Comma => (if shift { '<' } else { ',' }) as u32,
        Equal => (if shift { '+' } else { '=' }) as u32,
        LeftBracket => (if shift { '{' } else { '[' }) as u32,
        Minus => (if shift { '_' } else { '-' }) as u32,
        Period => (if shift { '>' } else { '.' }) as u32,
        RightBracket => (if shift { '}' } else { ']' }) as u32,
        Semicolon => (if shift { ':' } else { ';' }) as u32,
        Slash => (if shift { '?' } else { '/' }) as u32,
        Space => 0x0020,
        Backspace => 0xff08,
        Tab => 0xff09,
        Enter => 0xff0d,
        Escape => 0xff1b,
        Home => 0xff50,
        Left => 0xff51,
        Up => 0xff52,
        Right => 0xff53,
        Down => 0xff54,
        PageUp => 0xff55,
        PageDown => 0xff56,
        End => 0xff57,
        Insert => 0xff63,
        Delete => 0xffff,
        Pause => 0xff13,
        ScrollLock => 0xff14,
        NumLock => 0xff7f,
        Menu => 0xff67,
        CapsLock => 0xffe5,
        LeftShift => 0xffe1,
        RightShift => 0xffe2,
        LeftCtrl => 0xffe3,
        RightCtrl => 0xffe4,
        LeftAlt => 0xffe9,
        RightAlt => 0xffea,
        // macOS Screen Sharing maps the Super keysyms onto Command, so the Windows
        // key drives Cmd-C / Cmd-Tab on the far end.
        LeftSuper => 0xffeb,
        RightSuper => 0xffec,
        NumPadDot => 0xffae,
        NumPadSlash => 0xffaf,
        NumPadAsterisk => 0xffaa,
        NumPadMinus => 0xffad,
        NumPadPlus => 0xffab,
        NumPadEnter => 0xff8d,
        _ => return None,
    })
}

/// The keysym for a character the keyboard layout produced, or None if it is not
/// something to send as a character.
fn sym_for_char(c: u32) -> Option<u32> {
    // Control codes are what Windows reports for Ctrl combinations, and for Enter, Tab,
    // Backspace and Escape - all of which are sent as keys instead. Letting them
    // through here would send those twice.
    if c < 0x20 || c == 0x7f {
        return None;
    }
    // A character outside the basic plane arrives as the two halves of a surrogate
    // pair, and half a pair is worse than nothing. No server is going to type an emoji.
    if (0xd800..=0xdfff).contains(&c) {
        return None;
    }
    // Latin-1 is its own keysym; everything above it is the code point in the Unicode
    // block.
    Some(if c < 0x100 { c } else { 0x0100_0000 + c })
}

/// Characters Windows produced for the keys pressed since the last frame, in order.
///
/// Collected through minifb's input callback, which fires while the window pumps its
/// message queue, so by the time the frame's key lists are read these are already here
/// and the two can be matched up.
#[derive(Clone, Default)]
struct Typed(Arc<Mutex<Vec<u32>>>);

impl minifb::InputCallback for Typed {
    fn add_char(&mut self, c: u32) {
        self.0.lock().unwrap().push(c);
    }
}

/// Which monitor the server is showing (0 for all), how many it has, and the session's
/// encodings, which asking for another one repeats. Written by the network thread after
/// each frame, read by the window when Ctrl-Shift-M asks to switch.
type Monitors = Arc<Mutex<(usize, usize, Vec<i32>)>>;

/// The monitor after `shown` out of `n`: 1, 2 ... n, then all of them (0), then 1 again.
fn next_monitor(shown: usize, n: usize) -> usize {
    match shown {
        0 => 1,
        k if k >= n => 0,
        k => k + 1,
    }
}

/// Window pixel -> framebuffer pixel. AspectRatioStretch centres the image and
/// letterboxes it, so undo the scale and the bars before reporting a position.
fn to_fb(mx: f32, my: f32, win: (usize, usize), fb: (usize, usize)) -> (u16, u16) {
    let s = (win.0 as f32 / fb.0 as f32).min(win.1 as f32 / fb.1 as f32);
    let ox = (win.0 as f32 - fb.0 as f32 * s) / 2.0;
    let oy = (win.1 as f32 - fb.1 as f32 * s) / 2.0;
    let x = ((mx - ox) / s).clamp(0.0, fb.0 as f32 - 1.0);
    let y = ((my - oy) / s).clamp(0.0, fb.1 as f32 - 1.0);
    (x as u16, y as u16)
}

struct Input {
    w: Writer,
    /// `VNC_VIEW_ONLY=1`. Worth having: connecting to a production box and nudging
    /// the mouse into something is a real way to ruin an afternoon.
    view_only: bool,
    clip: Clip,
    board: Option<arboard::Clipboard>,
    /// Frames until the next clipboard poll. Reading the Windows clipboard 60 times
    /// a second is wasteful and fights other applications for the clipboard lock.
    clip_tick: u32,
    mask: u8,
    pos: (u16, u16),
    /// Key -> the keysym we sent on press. Releases must repeat that exact keysym:
    /// if shift comes up first, 'A' down followed by 'a' up leaves 'A' stuck down.
    held: HashMap<Key, u32>,
    /// What the keyboard layout made of the keys pressed this frame.
    typed: Typed,
    /// Scroll delta not yet worth a whole wheel click, carried to the next event
    /// rather than dropped. A touchpad's reported delta ranges from a fraction of a
    /// click to tens of them in one message, and rounding each message alone either
    /// floors a slow drag up to a full click every time or throws away the
    /// remainder of a fast flick - both of which is "scrolling feels slow".
    scroll_carry: f32,
    /// Raw delta units per wheel click sent. A plain mouse reports one notch as 12;
    /// a touchpad's driver decides its own units for the same physical swipe, and
    /// there is no way to ask it what they mean - so this is a knob, not a
    /// constant. `VNC_SCROLL_DIVISOR` overrides it without a rebuild.
    scroll_divisor: f32,
    monitors: Monitors,
}

impl Input {
    fn new(w: Writer, clip: Clip, monitors: Monitors) -> Input {
        let view_only = env::var("VNC_VIEW_ONLY").is_ok();
        if view_only {
            eprintln!("VNC_VIEW_ONLY set: input will not be sent");
        }
        let mut board = match arboard::Clipboard::new() {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("clipboard unavailable, sharing disabled: {e}");
                None
            }
        };
        // Seed with whatever is already on the local clipboard, so the first poll
        // sees no change. Otherwise merely connecting overwrites the remote
        // machine's clipboard with ours before you have copied anything.
        if let Some(b) = board.as_mut() {
            if let Ok(t) = b.get_text() {
                *clip.lock().unwrap() = t;
            }
        }
        Input {
            w,
            view_only,
            clip,
            board,
            clip_tick: 0,
            mask: 0,
            pos: (0, 0),
            held: HashMap::new(),
            typed: Typed::default(),
            scroll_carry: 0.0,
            scroll_divisor: env::var("VNC_SCROLL_DIVISOR")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|&d: &f32| d > 0.0)
                .unwrap_or(12.0),
            monitors,
        }
    }

    /// Send the local clipboard if it changed. Compared against the last text that
    /// crossed in either direction, so text pasted from the server is not bounced
    /// straight back at it.
    fn poll_clipboard(&mut self) -> Res<()> {
        if self.clip_tick > 0 {
            self.clip_tick -= 1;
            return Ok(());
        }
        self.clip_tick = 30; // twice a second at 60fps
        let Some(board) = self.board.as_mut() else {
            return Ok(());
        };
        let Ok(text) = board.get_text() else {
            return Ok(());
        };
        if text.is_empty() {
            return Ok(());
        }
        let mut last = self.clip.lock().unwrap();
        if *last == text {
            return Ok(());
        }
        *last = text.clone();
        drop(last);
        if debug() {
            eprintln!("[debug] clipboard -> server ({} bytes)", text.len());
        }
        send(&self.w, &cut_text_msg(&text))
    }

    fn key_event(&self, sym: u32, down: bool) -> Res<()> {
        input_sent();
        send(&self.w, &key_msg(sym, down))
    }

    fn pointer_event(&self, mask: u8, x: u16, y: u16) -> Res<()> {
        input_sent();
        send(&self.w, &pointer_msg(mask, x, y))
    }

    /// Where the pointer is on the remote screen, or None if it is outside the window.
    /// The same mapping the pointer events use, so the locally drawn cursor lands
    /// exactly where the server thinks the pointer is.
    fn pointer_at(&self, win: &Window, fb: (usize, usize)) -> Option<(i32, i32)> {
        let (mx, my) = win.get_mouse_pos(MouseMode::Discard)?;
        let (x, y) = to_fb(mx, my, win.get_size(), fb);
        Some((x as i32, y as i32))
    }

    fn pump(&mut self, win: &Window, fb: (usize, usize)) -> Res<()> {
        // Ctrl-Shift-M shows the server's next monitor. Ahead of the view-only check,
        // because choosing what to look at changes nothing on the remote machine. Only
        // vncfree-server has more than one to offer; with any other this does nothing.
        let held = |a, b| win.is_key_down(a) || win.is_key_down(b);
        let hotkey = held(Key::LeftCtrl, Key::RightCtrl) && held(Key::LeftShift, Key::RightShift);
        if hotkey && win.is_key_pressed(Key::M, KeyRepeat::No) {
            let (shown, n, enc) = self.monitors.lock().unwrap().clone();
            if n > 1 {
                share_monitor(&self.w, &enc, next_monitor(shown, n))?;
            }
        }
        // View-only suppresses the clipboard too: ClientCutText overwrites the
        // remote clipboard, which is still reaching over and changing something.
        if self.view_only {
            return Ok(());
        }
        self.poll_clipboard()?;
        if let Some((mx, my)) = win.get_mouse_pos(MouseMode::Discard) {
            let (x, y) = to_fb(mx, my, win.get_size(), fb);
            let mut mask = 0u8;
            if win.get_mouse_down(MouseButton::Left) {
                mask |= 1;
            }
            if win.get_mouse_down(MouseButton::Middle) {
                mask |= 2;
            }
            if win.get_mouse_down(MouseButton::Right) {
                mask |= 4;
            }
            if (mask, x, y) != (self.mask, self.pos.0, self.pos.1) {
                self.pointer_event(mask, x, y)?;
                (self.mask, self.pos) = (mask, (x, y));
            }
            // RFB has no scroll message: the wheel is buttons 4/5, clicked and
            // released, so a delta has to become some number of whole clicks.
            // minifb reports a plain mouse wheel notch as magnitude 12; a trackpad
            // reports anywhere from a fraction of that to several hundred in one
            // message, depending on how hard it was flicked. Carrying the remainder
            // to the next event means a slow drag still adds up to real clicks
            // instead of one per message regardless of size, and there is no cap on
            // a fast flick - it scrolls exactly as far as the delta says to.
            if let Some((_, sy)) = win.get_scroll_wheel() {
                if sy != 0.0 {
                    self.scroll_carry += sy;
                    let clicks_f = (self.scroll_carry / self.scroll_divisor).trunc();
                    self.scroll_carry -= clicks_f * self.scroll_divisor;
                    let clicks = clicks_f.abs() as u32;
                    if clicks > 0 {
                        let dir = if clicks_f > 0.0 { 8 } else { 16 };
                        for _ in 0..clicks {
                            self.pointer_event(mask | dir, x, y)?;
                            self.pointer_event(mask, x, y)?;
                        }
                    }
                }
            }
        }

        let shift = win.is_key_down(Key::LeftShift) || win.is_key_down(Key::RightShift);
        // Presses before releases: a key tapped and released inside one 60fps frame
        // shows up in both lists, and handling the release first would send an up
        // with nothing held, then a down that never gets released - a stuck key.
        let ctrl = win.is_key_down(Key::LeftCtrl) || win.is_key_down(Key::RightCtrl);
        let alt = win.is_key_down(Key::LeftAlt) || win.is_key_down(Key::RightAlt);

        // AltGr is how most layouts outside the US reach @ and the euro sign, and Windows
        // reports it as right Alt *plus a synthetic left Ctrl*. Forwarding those would
        // turn every AltGr character into a Ctrl-Alt shortcut on the far end, so while
        // it is down the modifiers it invents are held back and only the character it
        // produced is sent. Anything genuinely held before it went down is released.
        let altgr = win.is_key_down(Key::RightAlt);
        if altgr {
            for k in [Key::LeftCtrl, Key::RightCtrl, Key::LeftAlt, Key::RightAlt] {
                if let Some(sym) = self.held.remove(&k) {
                    self.key_event(sym, false)?;
                }
            }
        }

        // Ctrl and Alt shortcuts come from the table: Ctrl-C should be Ctrl-C wherever
        // the C key physically sits, and Windows reports the character for those as an
        // unusable control code anyway.
        let shortcut = (ctrl || alt) && !altgr;

        for k in win.get_keys_pressed(KeyRepeat::Yes) {
            // Ctrl-Shift-V types the local clipboard at the remote machine, for
            // servers that will not share one. Deliberately not Ctrl-V or Cmd-V:
            // those still legitimately paste the *remote* machine's own clipboard,
            // and taking them over would break something that already works.
            if k == Key::V && ctrl && shift {
                // The remote thinks Ctrl and Shift are held, because they are. Let go
                // of them there before typing, or every character arrives as a
                // shortcut.
                self.release_all()?;
                self.type_clipboard()?;
                // Sentinel: swallowed here, so nothing is sent for it and the repeat
                // does not fire the paste again on the next frame.
                self.held.insert(k, 0);
                continue;
            }
            // Ctrl-Shift-M, handled above: swallowed, like Ctrl-Shift-V.
            if k == Key::M && ctrl && shift {
                self.held.insert(k, 0);
                continue;
            }
            if altgr
                && matches!(
                    k,
                    Key::LeftCtrl | Key::RightCtrl | Key::LeftAlt | Key::RightAlt
                )
            {
                continue;
            }
            // A key that produces a character is left to the character callback, which
            // knows the layout. Sending the table's guess as well would type everything
            // twice.
            if types_a_character(k) && !shortcut {
                continue;
            }
            if let Some(sym) = keysym(k, shift) {
                self.held.insert(k, sym);
                self.key_event(sym, true)?;
            }
        }

        // Between the presses and the releases, so a character typed with shift lands
        // inside the shift the loop above just sent.
        let typed = std::mem::take(&mut *self.typed.0.lock().unwrap());
        if !shortcut {
            for sym in typed.into_iter().filter_map(sym_for_char) {
                // Down and straight back up. The character callback reports that
                // something was typed, not that a key is being held, and Windows
                // repeats it by itself while the key stays down.
                self.key_event(sym, true)?;
                self.key_event(sym, false)?;
            }
        }

        for k in win.get_keys_released() {
            match self.held.remove(&k) {
                Some(0) => {} // swallowed locally; nothing was ever sent
                Some(sym) => self.key_event(sym, false)?,
                None => {}
            }
        }
        Ok(())
    }

    /// Type the local clipboard at the remote machine, one key at a time.
    ///
    /// The escape hatch for servers that do not share a clipboard - macOS being the
    /// one that prompted it. Runs on its own thread: a long clipboard takes seconds
    /// and the window must keep drawing.
    fn type_clipboard(&mut self) -> Res<()> {
        let Some(board) = self.board.as_mut() else {
            return Ok(());
        };
        let Ok(text) = board.get_text() else {
            return Ok(());
        };
        if text.is_empty() {
            return Ok(());
        }
        let keys = typed_keys(&text);
        let sent = keys.len().min(MAX_TYPED);
        if keys.len() > MAX_TYPED {
            eprintln!(
                "clipboard is {} keys, typing the first {MAX_TYPED}",
                keys.len()
            );
        } else if debug() {
            eprintln!("[debug] typing {sent} key(s) from the clipboard");
        }

        let w = self.w.clone();
        std::thread::spawn(move || {
            for &(sym, shift) in keys.iter().take(sent) {
                let step = || -> Res<()> {
                    if shift {
                        send(&w, &key_msg(0xffe1, true))?; // Shift_L
                    }
                    send(&w, &key_msg(sym, true))?;
                    send(&w, &key_msg(sym, false))?;
                    if shift {
                        send(&w, &key_msg(0xffe1, false))?;
                    }
                    Ok(())
                };
                if step().is_err() {
                    return; // the link went away; the reconnect will sort it out
                }
                // Slow enough that a remote which drops keys under load keeps up.
                std::thread::sleep(std::time::Duration::from_millis(8));
            }
        });
        Ok(())
    }

    /// Called when the window loses focus. Without this, alt-tabbing while holding a
    /// modifier leaves it stuck down on the remote machine.
    fn release_all(&mut self) -> Res<()> {
        for (_, sym) in std::mem::take(&mut self.held) {
            if sym != 0 {
                self.key_event(sym, false)?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- window

/// One connection's lifetime: request updates, decode them, publish frames. Returns
/// when the link drops, which is normal rather than fatal - the caller reconnects.
fn session(
    mut vnc: Vnc,
    frame: &Arc<Mutex<Screen>>,
    alive: &AtomicBool,
    dirty: &AtomicBool,
    monitors: &Monitors,
) -> Res<()> {
    let mut board = arboard::Clipboard::new().ok();
    // One full frame to start with; from here the server is asked for the next one
    // the moment an update begins arriving.
    vnc.request(false)?;
    vnc.pipeline = env::var("VNC_NO_PIPELINE").is_err();
    while alive.load(Ordering::Relaxed) {
        if !vnc.pipeline {
            vnc.request(true)?;
        }
        let t = std::time::Instant::now();
        while !vnc.pump()? {
            if let Some(text) = vnc.pending_paste.take() {
                if let Some(b) = board.as_mut() {
                    let _ = b.set_text(text);
                }
            }
        }
        // Reading and decoding. Includes waiting for the server, so on an idle screen
        // this is mostly the wait, not the work.
        tick(&TIMING.decode_us, &TIMING.decode_max_us, t);
        TIMING.frames.fetch_add(1, Ordering::Relaxed);

        let t = std::time::Instant::now();
        let mut f = frame.lock().unwrap();
        tick(&TIMING.net_lock_us, &TIMING.net_lock_max_us, t);
        let t = std::time::Instant::now();
        if f.w != vnc.screen.w || f.h != vnc.screen.h {
            // The remote resolution changed, which happens when a Mac's display
            // settings change or a different machine answers on reconnect.
            f.w = vnc.screen.w;
            f.h = vnc.screen.h;
            f.px = vec![0; f.w * f.h];
            f.px.copy_from_slice(&vnc.screen.px);
        } else {
            // Only the regions this update touched. The rest is unchanged, and
            // copying it costs 8MB a frame at 1080p for nothing.
            let stride = f.w;
            for &(x, y, w, h) in &vnc.dirty {
                for row in y..y + h {
                    let o = row * stride + x;
                    f.px[o..o + w].copy_from_slice(&vnc.screen.px[o..o + w]);
                }
            }
        }
        tick(&TIMING.copy_us, &TIMING.copy_max_us, t);
        drop(f);
        // ponytail: a reconnect starts back on the server's default monitor.
        *monitors.lock().unwrap() = (
            vnc.dec.monitor,
            vnc.dec.monitors.len(),
            vnc.encodings.clone(),
        );
        dirty.store(true, Ordering::Relaxed);
    }
    Ok(())
}

/// How big to first open the window: as large as it can be while still fitting
/// inside this machine's work area, keeping the remote desktop's aspect ratio.
///
/// A server can hand over more pixels than "the screen" suggests - a Retina Mac's
/// framebuffer is double what its resolution looks like in System Settings, in each
/// direction - and without this the window opened at that full size, mostly off the
/// edge of a smaller local screen. `ScaleMode::AspectRatioStretch` already draws the
/// buffer scaled to whatever size the window actually is, so shrinking just the
/// starting size is enough; the window stays resizable for a 1:1 view afterwards.
fn initial_window_size(w: usize, h: usize) -> (usize, usize) {
    let mut area: RECT = unsafe { std::mem::zeroed() };
    let got = unsafe {
        SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            &mut area as *mut RECT as *mut std::ffi::c_void,
            0,
        )
    };
    if got == 0 {
        return (w, h);
    }
    let (avail_w, avail_h) = (
        (area.right - area.left) as f64,
        (area.bottom - area.top) as f64,
    );
    // A margin rather than the exact work area, so the title bar and borders still
    // leave the window entirely on screen instead of clipped by a pixel.
    let (budget_w, budget_h) = (avail_w * 0.9, avail_h * 0.85);
    let scale = (budget_w / w as f64).min(budget_h / h as f64).min(1.0);
    (
        ((w as f64 * scale).round() as usize).max(1),
        ((h as f64 * scale).round() as usize).max(1),
    )
}

fn run_window(vnc: Vnc, target: Target, clip: Clip, cursor: SharedCursor) -> Res<()> {
    let (w, h) = (vnc.screen.w, vnc.screen.h);
    let name = vnc.name.clone();
    let writer = vnc.w.clone();
    let frame = Arc::new(Mutex::new(Screen {
        w,
        h,
        px: vec![0; w * h],
    }));
    let alive = Arc::new(AtomicBool::new(true));
    let online = Arc::new(AtomicBool::new(true));
    let dirty = Arc::new(AtomicBool::new(true));
    let monitors = Monitors::default();
    let mut input = Input::new(writer.clone(), clip.clone(), monitors.clone());

    // Network on its own thread: reads block for as long as the remote screen is
    // idle, and the UI thread must never block on that.
    let (net_frame, net_alive, net_online) = (frame.clone(), alive.clone(), online.clone());
    let net_dirty = dirty.clone();
    let net_monitors = monitors.clone();
    // The same handle across reconnects, so a new session publishes its pointer shape
    // where the drawing thread is already looking.
    let net_cursor = cursor.clone();
    std::thread::spawn(move || {
        let mut first = Some(vnc);
        let mut backoff = 1u64;
        while net_alive.load(Ordering::Relaxed) {
            let fresh = match first.take() {
                Some(v) => Ok(v),
                None => Vnc::connect(&target, writer.clone(), clip.clone(), net_cursor.clone()),
            };
            match fresh {
                Ok(v) => {
                    backoff = 1;
                    net_online.store(true, Ordering::Relaxed);
                    if let Err(e) = session(v, &net_frame, &net_alive, &net_dirty, &net_monitors) {
                        eprintln!("connection lost: {e}");
                    }
                }
                Err(e) => eprintln!("reconnect failed: {e}"),
            }
            net_online.store(false, Ordering::Relaxed);
            *writer.lock().unwrap() = None;
            if !net_alive.load(Ordering::Relaxed) {
                return;
            }
            eprintln!("reconnecting in {backoff}s...");
            std::thread::sleep(std::time::Duration::from_secs(backoff));
            backoff = (backoff * 2).min(15);
        }
    });

    let opts = WindowOptions {
        resize: true,
        scale_mode: ScaleMode::AspectRatioStretch,
        ..Default::default()
    };
    let (iw, ih) = initial_window_size(w, h);
    let mut window = Window::new(&format!("{name} - vncfree"), iw, ih, opts)?;
    window.set_target_fps(60);
    // Characters land here as the window pumps its messages, with the keyboard layout
    // already applied by Windows.
    window.set_input_callback(Box::new(input.typed.clone()));

    // Escape is a key the remote machine wants, so closing the window is the only quit.
    let mut was_online = true;
    let mut was_shown = (0, 0);
    let mut size = (w, h);
    // What the pointer was painted over last time, so it can be lifted straight back
    // off, and where it was, so a move alone is enough to redraw.
    let mut under: Vec<u32> = Vec::new();
    let mut was_at: Option<(i32, i32)> = None;
    let mut hiding_pointer = false;
    let mut loop_at = std::time::Instant::now();
    let mut report_at = std::time::Instant::now();
    while window.is_open() && alive.load(Ordering::Relaxed) {
        let up = online.load(Ordering::Relaxed);
        let (shown, n, _) = *monitors.lock().unwrap();
        if up != was_online || (shown, n) != was_shown {
            let tag = if up { "" } else { " [reconnecting]" };
            // Which monitor, once there is a choice, so Ctrl-Shift-M visibly did something.
            let screen = match (shown, n) {
                (_, 0 | 1) => String::new(),
                (0, _) => " [all screens]".into(),
                (k, n) => format!(" [screen {k} of {n}]"),
            };
            window.set_title(&format!("{name} - vncfree{screen}{tag}"));
            (was_online, was_shown) = (up, (shown, n));
        }
        // How long the previous pass took, end to end. Keyboard input is only read
        // when this loop runs, so this *is* the input latency the person feels.
        tick(&TIMING.gap_us, &TIMING.gap_max_us, loop_at);
        loop_at = std::time::Instant::now();
        TIMING.loops.fetch_add(1, Ordering::Relaxed);
        if timing() && report_at.elapsed() >= std::time::Duration::from_secs(1) {
            TIMING.report(report_at.elapsed().as_secs_f64());
            report_at = std::time::Instant::now();
        }

        let t = std::time::Instant::now();
        if window.is_active() && up {
            input.pump(&window, size)?;
        } else if !input.held.is_empty() {
            input.release_all()?;
        }
        TIMING
            .input_us
            .fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
        // Where the pointer is now, in the remote screen's coordinates. Redraw when it
        // moves even if no frame arrived, because locally-drawn is the whole point:
        // waiting for the server would put the round trip straight back.
        let at = input.pointer_at(&window, size);
        let moved = at != was_at;
        was_at = at;

        // Only re-blit when a new frame actually arrived. Pushing an unchanged 1080p
        // buffer 60 times a second is megabytes of scaling and GDI work for nothing,
        // and it holds the frame lock the network thread is waiting on.
        if dirty.swap(false, Ordering::Relaxed) || moved {
            let t = std::time::Instant::now();
            let mut f = frame.lock().unwrap();
            tick(&TIMING.ui_lock_us, &TIMING.ui_lock_max_us, t);
            size = (f.w, f.h);
            // Painted and taken straight back off around the blit, so the buffer the
            // network thread writes into never contains a pointer. Leaving it there
            // between frames would mean the next partial update restores stale pixels
            // over whatever the server had just redrawn underneath it.
            let shape = cursor.lock().unwrap();
            // Two arrows on screen is worse than none, so the real one goes away for
            // as long as we have a picture of the remote one to draw instead.
            if shape.visible() != hiding_pointer {
                hiding_pointer = shape.visible();
                window.set_cursor_visibility(!hiding_pointer);
            }
            if let Some((x, y)) = at {
                shape.draw(&mut f, x, y, &mut under);
            }
            let t = std::time::Instant::now();
            window.update_with_buffer(&f.px, f.w, f.h)?;
            tick(&TIMING.blit_us, &TIMING.blit_max_us, t);
            restore(&mut f, &mut under);
        } else {
            let t = std::time::Instant::now();
            window.update();
            tick(&TIMING.blit_us, &TIMING.blit_max_us, t);
        }
    }
    alive.store(false, Ordering::Relaxed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ctrl-Shift-M walks 1, 2 ... n, then all of them, then back to 1.
    #[test]
    fn monitors_cycle_through_all_then_wrap() {
        let walk: Vec<usize> = std::iter::successors(Some(1), |&k| Some(next_monitor(k, 3)))
            .take(6)
            .collect();
        assert_eq!(walk, [1, 2, 3, 0, 1, 2]);
    }

    /// keysym() does range arithmetic on minifb's enum. If a future minifb reorders
    /// these variants that arithmetic silently produces wrong keys, so pin it here.
    #[test]
    fn minifb_key_variants_are_contiguous() {
        assert_eq!(Key::Z as u32 - Key::A as u32, 25);
        assert_eq!(Key::Key9 as u32 - Key::Key0 as u32, 9);
        assert_eq!(Key::F15 as u32 - Key::F1 as u32, 14);
        assert_eq!(Key::NumPad9 as u32 - Key::NumPad0 as u32, 9);
    }

    #[test]
    fn keysyms_cover_letters_digits_and_specials() {
        assert_eq!(keysym(Key::A, false), Some(0x61)); // 'a'
        assert_eq!(keysym(Key::A, true), Some(0x41)); // 'A'
        assert_eq!(keysym(Key::Z, false), Some(0x7a));
        assert_eq!(keysym(Key::Key1, false), Some(0x31)); // '1'
        assert_eq!(keysym(Key::Key1, true), Some(0x21)); // '!'
        assert_eq!(keysym(Key::Key0, true), Some(0x29)); // ')'
        assert_eq!(keysym(Key::Slash, true), Some(0x3f)); // '?'
        assert_eq!(keysym(Key::F1, false), Some(0xffbe));
        assert_eq!(keysym(Key::F12, false), Some(0xffc9));
        assert_eq!(keysym(Key::Enter, false), Some(0xff0d));
        assert_eq!(keysym(Key::LeftSuper, false), Some(0xffeb)); // Command on macOS
        assert_eq!(keysym(Key::Unknown, false), None);
    }

    /// Every key goes down exactly one of two routes: the character the layout produced,
    /// or the table. A key on both is typed twice, a key on neither does nothing at all,
    /// and both failures look like a broken keyboard rather than a mismatched list.
    #[test]
    fn each_key_takes_one_route_and_only_one() {
        use Key::*;
        let by_character = [
            A,
            M,
            Z,
            Key0,
            Key9,
            Apostrophe,
            Backquote,
            Backslash,
            Comma,
            Equal,
            LeftBracket,
            Minus,
            Period,
            RightBracket,
            Semicolon,
            Slash,
            Space,
            NumPad0,
            NumPad9,
            NumPadDot,
            NumPadSlash,
            NumPadAsterisk,
            NumPadMinus,
            NumPadPlus,
        ];
        let by_table = [
            Backspace,
            Tab,
            Enter,
            Escape,
            Home,
            Left,
            Up,
            Right,
            Down,
            PageUp,
            PageDown,
            End,
            Insert,
            Delete,
            Pause,
            ScrollLock,
            NumLock,
            Menu,
            CapsLock,
            LeftShift,
            RightShift,
            LeftCtrl,
            RightCtrl,
            LeftAlt,
            RightAlt,
            LeftSuper,
            RightSuper,
            NumPadEnter,
            F1,
            F12,
        ];
        for k in by_character {
            assert!(types_a_character(k), "{k:?} produces a character");
            // Still needs a table entry: with Ctrl held the shortcut wins over the
            // character, and a missing entry would make that combination do nothing.
            assert!(keysym(k, false).is_some(), "{k:?} also has a table entry");
        }
        for k in by_table {
            assert!(!types_a_character(k), "{k:?} is not a character key");
            assert!(keysym(k, false).is_some(), "{k:?} has a table entry");
        }
    }

    /// The character path is what makes a non-US layout work, so the keysym it derives
    /// has to be right for the three ranges a keyboard can produce.
    #[test]
    fn characters_become_the_right_keysyms() {
        // Latin-1 is its own keysym: 'a', and the UK pound sign.
        assert_eq!(sym_for_char('a' as u32), Some(0x61));
        assert_eq!(sym_for_char('\u{a3}' as u32), Some(0xa3), "pound sign");
        // Beyond that, the Unicode block. The euro is the one every AltGr layout has.
        assert_eq!(sym_for_char('\u{20ac}' as u32), Some(0x0100_20ac), "euro");
        // Control codes are keys, handled by the table, and must not arrive twice.
        assert_eq!(sym_for_char(0x0d), None, "Enter");
        assert_eq!(sym_for_char(0x08), None, "Backspace");
        assert_eq!(sym_for_char(0x03), None, "Ctrl-C");
        assert_eq!(sym_for_char(0x7f), None, "Delete");
        // Half of a surrogate pair is worse than nothing.
        assert_eq!(sym_for_char(0xd83d), None);
    }

    #[test]
    fn pointer_mapping_undoes_scale_and_letterbox() {
        // Same aspect ratio: pure 2x scale, no bars.
        assert_eq!(to_fb(800.0, 600.0, (1600, 1200), (800, 600)), (400, 300));
        // Wider window than framebuffer: 400px bars either side, scale 1.
        assert_eq!(to_fb(400.0, 0.0, (1600, 600), (800, 600)), (0, 0));
        assert_eq!(to_fb(800.0, 300.0, (1600, 600), (800, 600)), (400, 300));
        // Inside the bars, and past the right edge, both clamp into the framebuffer.
        assert_eq!(to_fb(0.0, 0.0, (1600, 600), (800, 600)), (0, 0));
        assert_eq!(to_fb(1599.0, 599.0, (1600, 600), (800, 600)), (799, 599));
    }
}
