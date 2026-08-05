//! vncfree - a free VNC (RFB) client for Windows.
//! Milestone 2: live window plus keyboard and mouse.
//! Pass an output path as a second argument for the headless one-frame PPM dump.

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use minifb::{Key, KeyRepeat, MouseButton, MouseMode, ScaleMode, Window, WindowOptions};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// Shared write half. Both the network thread (update requests) and the UI thread
/// (input events) write to this socket, and an interleaved write would desync the
/// protocol, so every whole message goes out under this lock.
type Writer = Arc<Mutex<TcpStream>>;

fn rd<const N: usize>(s: &mut impl Read) -> Res<[u8; N]> {
    let mut b = [0u8; N];
    s.read_exact(&mut b)?;
    Ok(b)
}
fn u8r(s: &mut impl Read) -> Res<u8> {
    Ok(rd::<1>(s)?[0])
}
fn u16r(s: &mut impl Read) -> Res<u16> {
    Ok(u16::from_be_bytes(rd::<2>(s)?))
}
fn u32r(s: &mut impl Read) -> Res<u32> {
    Ok(u32::from_be_bytes(rd::<4>(s)?))
}
fn i32r(s: &mut impl Read) -> Res<i32> {
    Ok(i32::from_be_bytes(rd::<4>(s)?))
}
fn blob(s: &mut impl Read, n: usize) -> Res<Vec<u8>> {
    let mut v = vec![0u8; n];
    s.read_exact(&mut v)?;
    Ok(v)
}
/// A u32-prefixed string, used by RFB for error reasons and the desktop name.
fn text(s: &mut impl Read) -> Res<String> {
    let n = u32r(s)? as usize;
    Ok(String::from_utf8_lossy(&blob(s, n)?).into_owned())
}

/// RFB's VNC-auth DES key: password truncated/zero-padded to 8 bytes, each byte
/// bit-reversed. The bit reversal is the part everyone gets wrong; see tests.
fn vnc_key(password: &str) -> [u8; 8] {
    let mut k = [0u8; 8];
    for (i, b) in password.bytes().take(8).enumerate() {
        k[i] = b.reverse_bits();
    }
    k
}

fn vnc_auth(r: &mut impl Read, w: &mut impl Write, password: &str) -> Res<()> {
    let mut challenge = rd::<16>(r)?;
    let cipher = Des::new(&vnc_key(password).into());
    for chunk in challenge.chunks_mut(8) {
        let mut b = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut b);
        chunk.copy_from_slice(&b);
    }
    w.write_all(&challenge)?;
    Ok(())
}

struct Screen {
    w: usize,
    h: usize,
    /// 0x00RRGGBB per pixel - exactly what minifb wants to blit.
    px: Vec<u32>,
}

struct Vnc {
    r: BufReader<TcpStream>,
    w: Writer,
    screen: Screen,
    name: String,
}

fn main() -> Res<()> {
    let args: Vec<String> = env::args().collect();
    let Some(addr) = args.get(1) else {
        eprintln!("usage: vncfree <host:port> [out.ppm]");
        eprintln!("  no out.ppm  -> open a live window");
        eprintln!("  out.ppm     -> grab one frame headless and exit");
        eprintln!("password is read from the VNC_PASSWORD env var");
        std::process::exit(2);
    };
    let password = env::var("VNC_PASSWORD").unwrap_or_default();
    let mut vnc = Vnc::connect(addr, &password)?;

    match args.get(2) {
        Some(out) => {
            vnc.request(false)?;
            while !vnc.pump()? {}
            write_ppm(out, &vnc.screen)?;
            println!("wrote {} ({}x{})", out, vnc.screen.w, vnc.screen.h);
            Ok(())
        }
        None => run_window(vnc),
    }
}

impl Vnc {
    fn connect(addr: &str, password: &str) -> Res<Vnc> {
        let tcp = TcpStream::connect(addr)?;
        tcp.set_nodelay(true)?;
        let mut w = tcp.try_clone()?;
        let mut r = BufReader::new(tcp);

        // --- version handshake ---
        let ver = String::from_utf8_lossy(&rd::<12>(&mut r)?).trim_end().to_string();
        // Apple's Screen Sharing announces "RFB 003.889". Replying 003.008 makes it
        // fall back to being a standard 3.8 server, so accept any 003.>=8 here.
        // ponytail: no 3.3/3.7 support - they negotiate SecurityResult differently.
        // Add them when a server actually refuses us.
        let minor: u32 = ver
            .strip_prefix("RFB 003.")
            .and_then(|m| m.parse().ok())
            .ok_or_else(|| format!("not an RFB 3.x server: {ver:?}"))?;
        if minor < 8 {
            return Err(format!("server speaks {ver:?}; vncfree needs RFB 003.008 or later").into());
        }
        w.write_all(b"RFB 003.008\n")?;

        // --- security handshake ---
        let n = u8r(&mut r)? as usize;
        if n == 0 {
            return Err(format!("server refused connection: {}", text(&mut r)?).into());
        }
        let types = blob(&mut r, n)?;
        let chosen = if types.contains(&1) {
            1 // None
        } else if types.contains(&2) {
            2 // VNC auth
        } else if types.contains(&30) {
            // Apple's Diffie-Hellman auth, used when a Mac is set to authenticate
            // against macOS user accounts. Not implemented - point at the fix.
            return Err("this Mac wants Apple's Diffie-Hellman auth (type 30), which \
                        vncfree does not implement yet. In System Settings > General > \
                        Sharing > Screen Sharing > (i), enable 'VNC viewers may control \
                        screen with password' and set an 8-character password."
                .into());
        } else {
            return Err(format!("no supported security type in {types:?}").into());
        };
        w.write_all(&[chosen])?;
        if chosen == 2 {
            if password.is_empty() {
                return Err("server wants a password; set VNC_PASSWORD".into());
            }
            vnc_auth(&mut r, &mut w, password)?;
        }
        if u32r(&mut r)? != 0 {
            return Err(format!("authentication failed: {}", text(&mut r)?).into());
        }

        // --- init ---
        w.write_all(&[1])?; // ClientInit, shared = yes
        let width = u16r(&mut r)? as usize;
        let height = u16r(&mut r)? as usize;
        let _server_format = rd::<16>(&mut r)?;
        let name = text(&mut r)?;
        eprintln!("connected: {name:?} {width}x{height} (server said {ver:?})");

        // Force our own pixel format so we never have to translate: 32bpp little-endian
        // true colour, shifts 16/8/0 => each pixel reads back as 0x00RRGGBB.
        #[rustfmt::skip]
        let set_format: [u8; 20] = [
            0, 0, 0, 0,               // msg type 0 + 3 padding
            32, 24, 0, 1,             // bpp, depth, big-endian=no, true-colour=yes
            0, 255, 0, 255, 0, 255,   // red/green/blue max (u16 each)
            16, 8, 0,                 // red/green/blue shift
            0, 0, 0,                  // padding
        ];
        w.write_all(&set_format)?;

        // SetEncodings: Raw only for now. Every server must support it.
        // ponytail: add CopyRect/Tight once bandwidth matters (milestone 3).
        w.write_all(&[2, 0, 0, 1])?;
        w.write_all(&0i32.to_be_bytes())?;

        let screen = Screen { w: width, h: height, px: vec![0; width * height] };
        Ok(Vnc { r, w: Arc::new(Mutex::new(w)), screen, name })
    }

    /// Ask for the whole screen. Incremental means "only what changed" - the server
    /// holds the request open until something does, which is what paces our loop.
    fn request(&mut self, incremental: bool) -> Res<()> {
        let mut req = vec![3, incremental as u8];
        req.extend_from_slice(&0u16.to_be_bytes());
        req.extend_from_slice(&0u16.to_be_bytes());
        req.extend_from_slice(&(self.screen.w as u16).to_be_bytes());
        req.extend_from_slice(&(self.screen.h as u16).to_be_bytes());
        self.w.lock().unwrap().write_all(&req)?;
        Ok(())
    }

    /// Read one server message. Returns true if it was a framebuffer update, i.e.
    /// the screen changed and is worth showing.
    fn pump(&mut self) -> Res<bool> {
        match u8r(&mut self.r)? {
            0 => {
                let _pad = u8r(&mut self.r)?;
                let rects = u16r(&mut self.r)?;
                for _ in 0..rects {
                    read_rect(&mut self.r, &mut self.screen)?;
                }
                Ok(true)
            }
            1 => {
                // SetColourMapEntries - we asked for true colour, so this is noise,
                // but we still have to consume it to stay in sync with the stream.
                blob(&mut self.r, 3)?;
                let n = u16r(&mut self.r)? as usize;
                blob(&mut self.r, n * 6)?;
                Ok(false)
            }
            2 => Ok(false), // Bell, no body
            3 => {
                // ServerCutText: 3 padding, then a u32-prefixed string
                blob(&mut self.r, 3)?;
                text(&mut self.r)?;
                Ok(false)
            }
            other => Err(format!("unexpected server message type {other}").into()),
        }
    }
}

// ---------------------------------------------------------------- input

/// X11 keysym for a minifb key, honouring shift. Printable ASCII keysyms are just
/// the character's ASCII value; everything else comes from the 0xff00 block.
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
        return Some(if shift { b")!@#$%^&*("[d] } else { b'0' + d as u8 } as u32);
    }
    if (F1 as u32..=F15 as u32).contains(&n) {
        return Some(0xffbe + (n - F1 as u32));
    }
    if (NumPad0 as u32..=NumPad9 as u32).contains(&n) {
        return Some(0xffb0 + (n - NumPad0 as u32));
    }
    // ponytail: US layout. Non-US punctuation needs minifb's character callback
    // instead of this table - add it when someone types on an AZERTY keyboard.
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

/// KeyEvent (msg 4): down-flag, 2 padding, then the keysym big-endian.
fn key_msg(sym: u32, down: bool) -> [u8; 8] {
    let s = sym.to_be_bytes();
    [4, down as u8, 0, 0, s[0], s[1], s[2], s[3]]
}

/// PointerEvent (msg 5): button mask, then x and y big-endian.
fn pointer_msg(mask: u8, x: u16, y: u16) -> [u8; 6] {
    let (x, y) = (x.to_be_bytes(), y.to_be_bytes());
    [5, mask, x[0], x[1], y[0], y[1]]
}

struct Input {
    w: Writer,
    mask: u8,
    pos: (u16, u16),
    /// Key -> the keysym we sent on press. Releases must repeat that exact keysym:
    /// if shift comes up first, 'A' down followed by 'a' up leaves 'A' stuck down.
    held: HashMap<Key, u32>,
}

impl Input {
    fn new(w: Writer) -> Input {
        Input { w, mask: 0, pos: (0, 0), held: HashMap::new() }
    }

    fn key_event(&self, sym: u32, down: bool) -> Res<()> {
        self.w.lock().unwrap().write_all(&key_msg(sym, down))?;
        Ok(())
    }

    fn pointer_event(&self, mask: u8, x: u16, y: u16) -> Res<()> {
        self.w.lock().unwrap().write_all(&pointer_msg(mask, x, y))?;
        Ok(())
    }

    fn pump(&mut self, win: &Window, fb: (usize, usize)) -> Res<()> {
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
            // RFB has no scroll message: the wheel is buttons 4/5, clicked and released.
            if let Some((_, sy)) = win.get_scroll_wheel() {
                if sy != 0.0 {
                    self.pointer_event(mask | if sy > 0.0 { 8 } else { 16 }, x, y)?;
                    self.pointer_event(mask, x, y)?;
                }
            }
        }

        let shift = win.is_key_down(Key::LeftShift) || win.is_key_down(Key::RightShift);
        // Presses before releases: a key tapped and released inside one 60fps frame
        // shows up in both lists, and handling the release first would send an up
        // with nothing held, then a down that never gets released - a stuck key.
        for k in win.get_keys_pressed(KeyRepeat::Yes) {
            if let Some(sym) = keysym(k, shift) {
                self.held.insert(k, sym);
                self.key_event(sym, true)?;
            }
        }
        for k in win.get_keys_released() {
            if let Some(sym) = self.held.remove(&k) {
                self.key_event(sym, false)?;
            }
        }
        Ok(())
    }

    /// Called when the window loses focus. Without this, alt-tabbing while holding a
    /// modifier leaves it stuck down on the remote machine.
    fn release_all(&mut self) -> Res<()> {
        for (_, sym) in std::mem::take(&mut self.held) {
            self.key_event(sym, false)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- window

fn run_window(mut vnc: Vnc) -> Res<()> {
    let (w, h) = (vnc.screen.w, vnc.screen.h);
    let title = format!("{} - vncfree", vnc.name);
    let frame = Arc::new(Mutex::new(vec![0u32; w * h]));
    let alive = Arc::new(AtomicBool::new(true));
    let mut input = Input::new(vnc.w.clone());

    // Network on its own thread: reads block for as long as the remote screen is
    // idle, and the UI thread must never block on that.
    let (net_frame, net_alive) = (frame.clone(), alive.clone());
    std::thread::spawn(move || {
        let mut incremental = false;
        while net_alive.load(Ordering::Relaxed) {
            let step = (|| -> Res<()> {
                vnc.request(incremental)?;
                while !vnc.pump()? {}
                net_frame.lock().unwrap().copy_from_slice(&vnc.screen.px);
                Ok(())
            })();
            if let Err(e) = step {
                eprintln!("connection lost: {e}");
                net_alive.store(false, Ordering::Relaxed);
                return;
            }
            incremental = true;
        }
    });

    let opts = WindowOptions {
        resize: true,
        scale_mode: ScaleMode::AspectRatioStretch,
        ..Default::default()
    };
    let mut window = Window::new(&title, w, h, opts)?;
    window.set_target_fps(60);

    // Escape is a key the remote machine wants, so closing the window is the only quit.
    while window.is_open() && alive.load(Ordering::Relaxed) {
        if window.is_active() {
            input.pump(&window, (w, h))?;
        } else if !input.held.is_empty() {
            input.release_all()?;
        }
        let px = frame.lock().unwrap();
        window.update_with_buffer(&px, w, h)?;
    }
    alive.store(false, Ordering::Relaxed);
    Ok(())
}

fn read_rect(r: &mut impl Read, s: &mut Screen) -> Res<()> {
    let x = u16r(r)? as usize;
    let y = u16r(r)? as usize;
    let w = u16r(r)? as usize;
    let h = u16r(r)? as usize;
    let enc = i32r(r)?;
    if enc != 0 {
        return Err(format!("encoding {enc} not implemented (Raw only)").into());
    }
    if x + w > s.w || y + h > s.h {
        return Err(format!("rect {x},{y} {w}x{h} outside {}x{} framebuffer", s.w, s.h).into());
    }
    let data = blob(r, w * h * 4)?;
    for row in 0..h {
        for col in 0..w {
            let p = (row * w + col) * 4;
            // Little-endian 32bpp with shifts 16/8/0 => bytes are B,G,R,pad.
            let rgb = (data[p + 2] as u32) << 16 | (data[p + 1] as u32) << 8 | data[p] as u32;
            s.px[(y + row) * s.w + x + col] = rgb;
        }
    }
    Ok(())
}

fn write_ppm(path: &str, s: &Screen) -> Res<()> {
    let mut f = BufWriter::new(File::create(path)?);
    write!(f, "P6\n{} {}\n255\n", s.w, s.h)?;
    let mut buf = Vec::with_capacity(s.px.len() * 3);
    for p in &s.px {
        buf.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, *p as u8]);
    }
    f.write_all(&buf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_reverses_bits_and_pads() {
        // 'A' is 0b0100_0001 -> reversed 0b1000_0010
        assert_eq!(vnc_key("A"), [0b1000_0010, 0, 0, 0, 0, 0, 0, 0]);
        // longer than 8 chars is truncated, not hashed
        assert_eq!(vnc_key("abcdefghij"), vnc_key("abcdefgh"));
        assert_eq!(vnc_key(""), [0; 8]);
    }

    #[test]
    fn raw_rect_lands_at_the_right_offset() {
        let mut s = Screen { w: 2, h: 2, px: vec![0; 4] };
        #[rustfmt::skip]
        let bytes: [u8; 16] = [
            0, 1,  0, 1,          // x=1, y=1
            0, 1,  0, 1,          // w=1, h=1
            0, 0, 0, 0,           // encoding = Raw
            0xAA, 0xBB, 0xCC, 0,  // one pixel: B, G, R, pad
        ];
        read_rect(&mut &bytes[..], &mut s).unwrap();
        assert_eq!(s.px, vec![0, 0, 0, 0x00CC_BBAA]);
    }

    #[test]
    fn rect_outside_the_framebuffer_is_rejected() {
        let mut s = Screen { w: 2, h: 2, px: vec![0; 4] };
        let bytes: [u8; 12] = [0, 1, 0, 1, 0, 4, 0, 4, 0, 0, 0, 0];
        assert!(read_rect(&mut &bytes[..], &mut s).is_err());
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

    /// These byte layouts were confirmed against a real TigerVNC server: the keysyms
    /// below showed up verbatim in the X server's event log.
    #[test]
    fn input_messages_match_the_wire_format() {
        assert_eq!(key_msg(0x61, true), [4, 1, 0, 0, 0, 0, 0, 0x61]); // 'a' down
        assert_eq!(key_msg(0x61, false), [4, 0, 0, 0, 0, 0, 0, 0x61]); // 'a' up
        assert_eq!(key_msg(0xff0d, true), [4, 1, 0, 0, 0, 0, 0xff, 0x0d]); // Return
        assert_eq!(pointer_msg(0, 640, 480), [5, 0, 0x02, 0x80, 0x01, 0xe0]);
        assert_eq!(pointer_msg(1, 1, 1), [5, 1, 0, 1, 0, 1]); // left button down
        assert_eq!(pointer_msg(8, 0, 0), [5, 8, 0, 0, 0, 0]); // wheel up
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
