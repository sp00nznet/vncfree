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

use aes::Aes128;
use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use md5::{Digest, Md5};
use minifb::{Key, KeyRepeat, MouseButton, MouseMode, ScaleMode, Window, WindowOptions};
use num_bigint::BigUint;

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

/// A big-endian integer in exactly `len` bytes, left-padded with zeros. Both the
/// shared secret and the public key are fixed-width on the wire: hashing a secret
/// that is one byte short silently produces a different AES key, and the only
/// symptom is the server saying authentication failed.
fn pad_be(n: &BigUint, len: usize) -> Vec<u8> {
    let b = n.to_bytes_be();
    assert!(b.len() <= len, "value is wider than the key length");
    let mut out = vec![0u8; len - b.len()];
    out.extend_from_slice(&b);
    out
}

/// Write a null-terminated string into a fixed field, leaving the rest of the field
/// as-is (Apple pre-fills the credential blob with random bytes, so the padding after
/// the terminator is random rather than zeros).
fn write_cstr(dst: &mut [u8], s: &str, what: &str) -> Res<()> {
    let b = s.as_bytes();
    if b.len() >= dst.len() {
        return Err(format!("{what} is too long: max {} bytes", dst.len() - 1).into());
    }
    dst[..b.len()].copy_from_slice(b);
    dst[b.len()] = 0;
    Ok(())
}

/// Apple's Diffie-Hellman authentication (security type 30), which is what macOS
/// Screen Sharing uses by default so it can check real macOS account credentials.
///
/// The server sends a generator, a key length, a prime and its public key. We do a
/// standard DH exchange, MD5 the shared secret into an AES-128 key, and return the
/// username and password encrypted in a 128-byte blob followed by our public key.
fn apple_dh_auth(
    r: &mut impl Read,
    w: &mut impl Write,
    username: &str,
    password: &str,
) -> Res<()> {
    let generator = u16r(r)?;
    let key_len = u16r(r)? as usize;
    let prime = blob(r, key_len)?;
    let server_pub = blob(r, key_len)?;

    let p = BigUint::from_bytes_be(&prime);
    if p == BigUint::from(0u32) {
        return Err("server sent a zero prime".into());
    }

    // Our DH private key. This must come from the OS CSPRNG - a predictable private
    // key hands the session to anyone who can watch the exchange.
    let mut private = vec![0u8; key_len];
    getrandom::fill(&mut private)?;

    let x = BigUint::from_bytes_be(&private);
    let client_pub = BigUint::from(generator).modpow(&x, &p);
    let shared = BigUint::from_bytes_be(&server_pub).modpow(&x, &p);
    let key: [u8; 16] = Md5::digest(pad_be(&shared, key_len)).into();

    // 128-byte credential blob: username at 0, password at 64, each null-terminated
    // inside its own 64-byte field, with the slack left as the random fill.
    let mut creds = [0u8; 128];
    getrandom::fill(&mut creds)?;
    let (user_field, pass_field) = creds.split_at_mut(64);
    write_cstr(user_field, username, "username")?;
    write_cstr(pass_field, password, "password")?;

    // AES-128-ECB, exactly 8 blocks, no padding.
    let cipher = Aes128::new(&key.into());
    for block in creds.chunks_mut(16) {
        let mut b = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut b);
        block.copy_from_slice(&b);
    }

    w.write_all(&creds)?;
    w.write_all(&pad_be(&client_pub, key_len))?;
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
        eprintln!("credentials come from VNC_PASSWORD, plus VNC_USERNAME for a Mac");
        std::process::exit(2);
    };
    let username = env::var("VNC_USERNAME").unwrap_or_default();
    let password = env::var("VNC_PASSWORD").unwrap_or_default();
    let mut vnc = Vnc::connect(addr, &username, &password)?;

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
    fn connect(addr: &str, username: &str, password: &str) -> Res<Vnc> {
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
            2 // VNC auth: DES, 8-character passwords, no username
        } else if types.contains(&30) {
            30 // Apple Diffie-Hellman: what macOS Screen Sharing offers by default
        } else {
            return Err(format!("no supported security type in {types:?}").into());
        };
        w.write_all(&[chosen])?;
        match chosen {
            2 => {
                if password.is_empty() {
                    return Err("server wants a password; set VNC_PASSWORD".into());
                }
                vnc_auth(&mut r, &mut w, password)?;
            }
            30 => {
                if username.is_empty() || password.is_empty() {
                    return Err("this Mac authenticates against a macOS account; set \
                                VNC_USERNAME and VNC_PASSWORD"
                        .into());
                }
                apple_dh_auth(&mut r, &mut w, username, password)?;
            }
            _ => {}
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

    /// 1024-bit MODP group (RFC 2409 group 2) - same 128-byte key length a Mac uses.
    const MODP_1024: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
        29024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6D\
        F25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
        EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

    /// Proves the primitives are wired up right, independently of the protocol.
    /// AES vector is FIPS-197 C.1; MD5 vector is RFC 1321.
    #[test]
    fn crypto_primitives_match_published_vectors() {
        let key: [u8; 16] = (0u8..16).collect::<Vec<_>>().try_into().unwrap();
        let mut block = GenericArray::clone_from_slice(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        Aes128::new(&key.into()).encrypt_block(&mut block);
        assert_eq!(
            block[..],
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70,
                0xb4, 0xc5, 0x5a
            ]
        );
        let md5: [u8; 16] = Md5::digest(b"abc").into();
        assert_eq!(
            md5,
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28,
                0xe1, 0x7f, 0x72
            ]
        );
    }

    #[test]
    fn fixed_width_padding_and_credential_fields() {
        assert_eq!(pad_be(&BigUint::from(1u32), 4), [0, 0, 0, 1]);
        assert_eq!(pad_be(&BigUint::from(0u32), 3), [0, 0, 0]);
        assert_eq!(pad_be(&BigUint::from(0x1234u32), 2), [0x12, 0x34]);

        // The field keeps its random fill after the null terminator.
        let mut f = [0xAAu8; 8];
        write_cstr(&mut f, "hi", "username").unwrap();
        assert_eq!(f, [b'h', b'i', 0, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
        // A string that would fill the field leaves no room for the terminator.
        assert!(write_cstr(&mut [0u8; 4], "abcd", "username").is_err());
        assert!(write_cstr(&mut [0u8; 4], "abc", "username").is_ok());
    }

    /// Stands in for the Mac: plays the server side of the exchange, then decrypts
    /// what we sent and checks the credentials come back out intact. This verifies
    /// the DH maths, the MD5-to-AES key derivation and the blob layout. It cannot
    /// verify Apple's field order, which is taken from the protocol description.
    #[test]
    fn apple_dh_round_trip_recovers_the_credentials() {
        use aes::cipher::BlockDecrypt;

        let p = BigUint::parse_bytes(MODP_1024.as_bytes(), 16).unwrap();
        let key_len = 128usize;
        assert_eq!(p.to_bytes_be().len(), key_len, "prime transcribed wrong");

        let server_priv = BigUint::from(0x0123_4567_89ABu64);
        let server_pub = BigUint::from(2u32).modpow(&server_priv, &p);

        let mut msg = Vec::new();
        msg.extend_from_slice(&2u16.to_be_bytes()); // generator
        msg.extend_from_slice(&(key_len as u16).to_be_bytes());
        msg.extend_from_slice(&pad_be(&p, key_len));
        msg.extend_from_slice(&pad_be(&server_pub, key_len));

        let mut out = Vec::new();
        apple_dh_auth(&mut &msg[..], &mut out, "alice", "hunter2").unwrap();
        assert_eq!(out.len(), 128 + key_len, "blob then public key");

        // Server side: derive the same key from our public key and decrypt.
        let (ciphertext, client_pub) = out.split_at(128);
        let shared = BigUint::from_bytes_be(client_pub).modpow(&server_priv, &p);
        let key: [u8; 16] = Md5::digest(pad_be(&shared, key_len)).into();
        let cipher = Aes128::new(&key.into());
        let mut plain = ciphertext.to_vec();
        for block in plain.chunks_mut(16) {
            let mut b = GenericArray::clone_from_slice(block);
            cipher.decrypt_block(&mut b);
            block.copy_from_slice(&b);
        }

        let field = |f: &[u8]| {
            String::from_utf8(f[..f.iter().position(|&c| c == 0).unwrap()].to_vec()).unwrap()
        };
        assert_eq!(field(&plain[..64]), "alice");
        assert_eq!(field(&plain[64..]), "hunter2");
    }

    /// Two runs must differ: the private key and the blob padding are random, so
    /// identical output would mean the CSPRNG is not being used at all.
    #[test]
    fn apple_dh_output_is_not_deterministic() {
        let p = BigUint::parse_bytes(MODP_1024.as_bytes(), 16).unwrap();
        let key_len = 128usize;
        let server_pub = BigUint::from(2u32).modpow(&BigUint::from(99u32), &p);
        let mut msg = Vec::new();
        msg.extend_from_slice(&2u16.to_be_bytes());
        msg.extend_from_slice(&(key_len as u16).to_be_bytes());
        msg.extend_from_slice(&pad_be(&p, key_len));
        msg.extend_from_slice(&pad_be(&server_pub, key_len));

        let mut a = Vec::new();
        let mut b = Vec::new();
        apple_dh_auth(&mut &msg[..], &mut a, "alice", "hunter2").unwrap();
        apple_dh_auth(&mut &msg[..], &mut b, "alice", "hunter2").unwrap();
        assert_ne!(a, b);
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
