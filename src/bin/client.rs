//! vncfree - a free VNC (RFB) client for Windows.
//!
//! Live window, keyboard and mouse, shared clipboard, automatic reconnect. Speaks
//! RFB 3.8 with Raw, CopyRect and ZRLE encodings, and authenticates with either
//! classic VNC auth or Apple's Diffie-Hellman scheme for macOS.
//!
//! Run with no arguments and it asks where to connect. Given an address it connects
//! straight away, and a second argument is a path for a headless one-frame PPM dump.
//! Settings come from the environment: VNC_USERNAME, VNC_PASSWORD, VNC_VIEW_ONLY,
//! VNC_RAW_ONLY, VNC_DEBUG.

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use md5::{Digest, Md5};
use minifb::{Key, KeyRepeat, MouseButton, MouseMode, ScaleMode, Window, WindowOptions};
use num_bigint::BigUint;

use vncfree::{
    blob, cut_text_msg, debug, from_latin1, i32r, rd, text, u16r, u32r, u8r, vnc_des, Res, Screen,
    PIXEL_FORMAT,
};

/// Shared write half. Both the network thread (update requests) and the UI thread
/// (input events) write to this socket, and an interleaved write would desync the
/// protocol, so every whole message goes out under this lock.
type Writer = Arc<Mutex<Option<TcpStream>>>;

/// Write one whole message. Does nothing while disconnected: input and clipboard
/// events raised during a reconnect have nowhere to go, and that is not an error.
fn send(w: &Writer, bytes: &[u8]) -> Res<()> {
    if let Some(s) = w.lock().unwrap().as_mut() {
        s.write_all(bytes)?;
    }
    Ok(())
}

fn vnc_auth(r: &mut impl Read, w: &mut impl Write, password: &str) -> Res<()> {
    let mut challenge = rd::<16>(r)?;
    vnc_des(&mut challenge, password);
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
fn apple_dh_auth(r: &mut impl Read, w: &mut impl Write, username: &str, password: &str) -> Res<()> {
    let generator = u16r(r)?;
    let key_len = u16r(r)? as usize;
    let prime = blob(r, key_len)?;
    let server_pub = blob(r, key_len)?;
    if debug() {
        eprintln!("[debug] apple-dh generator={generator} key-length={key_len} bytes");
    }

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

/// Everything needed to open the connection again after it drops.
struct Target {
    addr: String,
    user: String,
    pass: String,
}

struct Vnc {
    r: BufReader<TcpStream>,
    w: Writer,
    screen: Screen,
    name: String,
    dec: Decoder,
    clip: Clip,
    /// Text the server sent us, waiting to go onto the Windows clipboard. The
    /// clipboard handle itself is not held here because this struct moves between
    /// threads on every reconnect.
    pending_paste: Option<String>,
}

impl Vnc {
    fn paste(&mut self, text: String) {
        *self.clip.lock().unwrap() = text.clone();
        self.pending_paste = Some(text);
    }
}

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
        vncfree::gui::Field::new("Password", true, false),
    ];
    let note = "Address is host:port, for example 192.168.1.50:5900.";
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
        // A Mac authenticates against a macOS account and still needs a username;
        // there is no box for it, so it comes from the environment.
        user: env::var("VNC_USERNAME").unwrap_or_default(),
        pass: fields[1].value.clone(),
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
    let mut vnc = Vnc::connect(&target, writer, clip.clone())?;

    match args.get(2) {
        Some(out) => {
            vnc.request(false)?;
            while !vnc.pump()? {}
            write_ppm(out, &vnc.screen)?;
            println!("wrote {} ({}x{})", out, vnc.screen.w, vnc.screen.h);
            Ok(())
        }
        None => run_window(vnc, target, clip),
    }
}

impl Vnc {
    /// `out` is the shared write half. It is published only once the handshake has
    /// fully succeeded, so the UI thread can never write input into a half-open
    /// connection. Handshake writes go direct to the socket and skip the lock.
    fn connect(t: &Target, out: Writer, clip: Clip) -> Res<Vnc> {
        let (addr, username, password) = (&t.addr, &t.user, &t.pass);
        // A bounded timeout, because the OS default is around twenty seconds of
        // nothing at all if the address is wrong.
        let resolved = addr
            .to_socket_addrs()
            .map_err(|e| format!("{addr:?} is not a usable address: {e}"))?
            .next()
            .ok_or_else(|| format!("{addr:?} did not resolve to anything"))?;
        let tcp = TcpStream::connect_timeout(&resolved, std::time::Duration::from_secs(10))
            .map_err(|e| format!("could not connect to {addr}: {e}"))?;
        tcp.set_nodelay(true)?;
        let mut w = tcp.try_clone()?;
        let mut r = BufReader::new(tcp);

        // --- version handshake ---
        let ver = String::from_utf8_lossy(&rd::<12>(&mut r)?)
            .trim_end()
            .to_string();
        // Apple's Screen Sharing announces "RFB 003.889". Replying 003.008 makes it
        // fall back to being a standard 3.8 server, so accept any 003.>=8 here.
        // ponytail: no 3.3/3.7 support - they negotiate SecurityResult differently.
        // Add them when a server actually refuses us.
        let minor: u32 = ver
            .strip_prefix("RFB 003.")
            .and_then(|m| m.parse().ok())
            .ok_or_else(|| format!("not an RFB 3.x server: {ver:?}"))?;
        if minor < 8 {
            return Err(
                format!("server speaks {ver:?}; vncfree needs RFB 003.008 or later").into(),
            );
        }
        w.write_all(b"RFB 003.008\n")?;

        // --- security handshake ---
        let n = u8r(&mut r)? as usize;
        if n == 0 {
            return Err(format!("server refused connection: {}", text(&mut r)?).into());
        }
        let types = blob(&mut r, n)?;
        if debug() {
            eprintln!("[debug] server version {ver:?}, security types offered {types:?}");
        }
        let chosen = if types.contains(&1) {
            1 // None
        } else if types.contains(&2) {
            2 // VNC auth: DES, 8-character passwords, no username
        } else if types.contains(&30) {
            30 // Apple Diffie-Hellman: what macOS Screen Sharing offers by default
        } else {
            return Err(format!("no supported security type in {types:?}").into());
        };
        if debug() {
            eprintln!("[debug] chose security type {chosen}");
        }
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
            let why = text(&mut r)?;
            if chosen == 30 {
                return Err(format!(
                    "authentication failed: {why}\n\
                     The Diffie-Hellman exchange completed, so the Mac read our \
                     credentials and refused them. A macOS account that logs in fine \
                     locally is still refused here unless it is separately authorised \
                     for remote access. On the Mac:\n\
                     - grant access to every account:\n    \
                     sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app\\\n      \
                     /Contents/Resources/kickstart -configure -allowAccessFor -allUsers \
                     -privs -all -restart -agent\n\
                     - or System Settings > General > Sharing > Remote Management (or \
                     Screen Sharing) > (i), add the account and tick Observe/Control\n\
                     - use the account's short name (`whoami`), not its full name"
                )
                .into());
            }
            return Err(format!("authentication failed: {why}").into());
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
        let mut set_format = vec![0u8, 0, 0, 0]; // msg type 0 + 3 padding
        set_format.extend_from_slice(&PIXEL_FORMAT);
        w.write_all(&set_format)?;

        // SetEncodings, most preferred first. Raw is always last so that a server
        // supporting neither of the others still works - the fallback is automatic.
        // ponytail: no Tight. It needs four persistent zlib streams and a JPEG
        // decoder, and ZRLE already gets most of the win. Add it if a real server
        // turns out to offer Tight but not ZRLE.
        let encodings: &[i32] = if env::var("VNC_RAW_ONLY").is_ok() {
            eprintln!("VNC_RAW_ONLY set: requesting Raw only");
            &[0]
        } else {
            &[16, 1, 0] // ZRLE, CopyRect, Raw
        };
        w.write_all(&[2, 0])?;
        w.write_all(&(encodings.len() as u16).to_be_bytes())?;
        for e in encodings {
            w.write_all(&e.to_be_bytes())?;
        }

        let screen = Screen {
            w: width,
            h: height,
            px: vec![0; width * height],
        };
        *out.lock().unwrap() = Some(w);
        Ok(Vnc {
            r,
            w: out,
            screen,
            name,
            dec: Decoder::new(),
            clip,
            pending_paste: None,
        })
    }

    /// Ask for the whole screen. Incremental means "only what changed" - the server
    /// holds the request open until something does, which is what paces our loop.
    fn request(&mut self, incremental: bool) -> Res<()> {
        let mut req = vec![3, incremental as u8];
        req.extend_from_slice(&0u16.to_be_bytes());
        req.extend_from_slice(&0u16.to_be_bytes());
        req.extend_from_slice(&(self.screen.w as u16).to_be_bytes());
        req.extend_from_slice(&(self.screen.h as u16).to_be_bytes());
        send(&self.w, &req)
    }

    /// Read one server message. Returns true if it was a framebuffer update, i.e.
    /// the screen changed and is worth showing.
    fn pump(&mut self) -> Res<bool> {
        match u8r(&mut self.r)? {
            0 => {
                let _pad = u8r(&mut self.r)?;
                let rects = u16r(&mut self.r)?;
                for _ in 0..rects {
                    self.dec.rect(&mut self.r, &mut self.screen)?;
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
                // ServerCutText: 3 padding, then a u32-prefixed Latin-1 string.
                blob(&mut self.r, 3)?;
                let n = u32r(&mut self.r)? as usize;
                let body = blob(&mut self.r, n)?;
                if debug() {
                    eprintln!("[debug] clipboard <- server ({n} bytes)");
                }
                self.paste(from_latin1(&body));
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

/// Remembers the last clipboard text that crossed the link in either direction.
/// Without it, text received from the server is immediately detected as a local
/// clipboard change and sent straight back, and the two ends ping-pong forever.
type Clip = Arc<Mutex<String>>;

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
}

impl Input {
    fn new(w: Writer, clip: Clip) -> Input {
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
        send(&self.w, &key_msg(sym, down))
    }

    fn pointer_event(&self, mask: u8, x: u16, y: u16) -> Res<()> {
        send(&self.w, &pointer_msg(mask, x, y))
    }

    fn pump(&mut self, win: &Window, fb: (usize, usize)) -> Res<()> {
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

/// One connection's lifetime: request updates, decode them, publish frames. Returns
/// when the link drops, which is normal rather than fatal - the caller reconnects.
fn session(
    mut vnc: Vnc,
    frame: &Arc<Mutex<Screen>>,
    alive: &AtomicBool,
    dirty: &AtomicBool,
) -> Res<()> {
    let mut board = arboard::Clipboard::new().ok();
    let mut incremental = false;
    while alive.load(Ordering::Relaxed) {
        vnc.request(incremental)?;
        while !vnc.pump()? {
            if let Some(text) = vnc.pending_paste.take() {
                if let Some(b) = board.as_mut() {
                    let _ = b.set_text(text);
                }
            }
        }
        let mut f = frame.lock().unwrap();
        if f.w != vnc.screen.w || f.h != vnc.screen.h {
            // The remote resolution changed, which happens when a Mac's display
            // settings change or a different machine answers on reconnect.
            f.w = vnc.screen.w;
            f.h = vnc.screen.h;
            f.px = vec![0; f.w * f.h];
        }
        f.px.copy_from_slice(&vnc.screen.px);
        drop(f);
        dirty.store(true, Ordering::Relaxed);
        incremental = true;
    }
    Ok(())
}

fn run_window(vnc: Vnc, target: Target, clip: Clip) -> Res<()> {
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
    let mut input = Input::new(writer.clone(), clip.clone());

    // Network on its own thread: reads block for as long as the remote screen is
    // idle, and the UI thread must never block on that.
    let (net_frame, net_alive, net_online) = (frame.clone(), alive.clone(), online.clone());
    let net_dirty = dirty.clone();
    std::thread::spawn(move || {
        let mut first = Some(vnc);
        let mut backoff = 1u64;
        while net_alive.load(Ordering::Relaxed) {
            let fresh = match first.take() {
                Some(v) => Ok(v),
                None => Vnc::connect(&target, writer.clone(), clip.clone()),
            };
            match fresh {
                Ok(v) => {
                    backoff = 1;
                    net_online.store(true, Ordering::Relaxed);
                    if let Err(e) = session(v, &net_frame, &net_alive, &net_dirty) {
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
    let mut window = Window::new(&format!("{name} - vncfree"), w, h, opts)?;
    window.set_target_fps(60);

    // Escape is a key the remote machine wants, so closing the window is the only quit.
    let mut was_online = true;
    let mut size = (w, h);
    while window.is_open() && alive.load(Ordering::Relaxed) {
        let up = online.load(Ordering::Relaxed);
        if up != was_online {
            let tag = if up { "" } else { " [reconnecting]" };
            window.set_title(&format!("{name} - vncfree{tag}"));
            was_online = up;
        }
        if window.is_active() && up {
            input.pump(&window, size)?;
        } else if !input.held.is_empty() {
            input.release_all()?;
        }
        // Only re-blit when a new frame actually arrived. Pushing an unchanged 1080p
        // buffer 60 times a second is megabytes of scaling and GDI work for nothing,
        // and it holds the frame lock the network thread is waiting on.
        if dirty.swap(false, Ordering::Relaxed) {
            let f = frame.lock().unwrap();
            size = (f.w, f.h);
            window.update_with_buffer(&f.px, f.w, f.h)?;
        } else {
            window.update();
        }
    }
    alive.store(false, Ordering::Relaxed);
    Ok(())
}

// ---------------------------------------------------------------- decoding

/// A ZRLE "compressed pixel". Our pixel format puts all the colour in the low 3
/// bytes, so CPIXELs drop the unused fourth byte: little-endian B, G, R.
fn cpixel(r: &mut impl Read) -> Res<u32> {
    let b = rd::<3>(r)?;
    Ok((b[2] as u32) << 16 | (b[1] as u32) << 8 | b[0] as u32)
}

/// A ZRLE run length: one more than the sum of the bytes, where 255 means "keep
/// reading". So a run of 256 arrives as 255, 0.
fn run_len(r: &mut impl Read) -> Res<usize> {
    let mut len = 1usize;
    loop {
        let b = u8r(r)?;
        len += b as usize;
        if b != 255 {
            return Ok(len);
        }
    }
}

struct Decoder {
    /// ZRLE's zlib stream spans the whole connection, not one rectangle. Resetting
    /// it per rectangle decodes the first one and then produces garbage forever.
    zlib: flate2::Decompress,
}

impl Decoder {
    fn new() -> Decoder {
        Decoder {
            zlib: flate2::Decompress::new(true),
        }
    }

    fn rect(&mut self, r: &mut impl Read, s: &mut Screen) -> Res<()> {
        let x = u16r(r)? as usize;
        let y = u16r(r)? as usize;
        let w = u16r(r)? as usize;
        let h = u16r(r)? as usize;
        let enc = i32r(r)?;
        if x + w > s.w || y + h > s.h {
            return Err(format!("rect {x},{y} {w}x{h} outside {}x{} framebuffer", s.w, s.h).into());
        }
        match enc {
            0 => self.raw(r, s, x, y, w, h),
            1 => self.copy_rect(r, s, x, y, w, h),
            16 => self.zrle(r, s, x, y, w, h),
            _ => Err(format!("encoding {enc} not implemented").into()),
        }
    }

    fn raw(
        &mut self,
        r: &mut impl Read,
        s: &mut Screen,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    ) -> Res<()> {
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

    /// Copy a block already on screen somewhere else - what a server sends when you
    /// drag a window or scroll. Source and destination overlap constantly, so the
    /// rows go via a scratch buffer rather than being copied in place.
    fn copy_rect(
        &mut self,
        r: &mut impl Read,
        s: &mut Screen,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    ) -> Res<()> {
        let sx = u16r(r)? as usize;
        let sy = u16r(r)? as usize;
        if sx + w > s.w || sy + h > s.h {
            return Err(format!("copyrect source {sx},{sy} {w}x{h} is off-screen").into());
        }
        let mut tmp = Vec::with_capacity(w * h);
        for row in 0..h {
            let o = (sy + row) * s.w + sx;
            tmp.extend_from_slice(&s.px[o..o + w]);
        }
        for row in 0..h {
            let o = (y + row) * s.w + x;
            s.px[o..o + w].copy_from_slice(&tmp[row * w..(row + 1) * w]);
        }
        Ok(())
    }

    /// Feed one rectangle's bytes through the connection-wide zlib stream.
    fn inflate(&mut self, input: &[u8], expect: usize) -> Res<Vec<u8>> {
        let mut out = Vec::with_capacity(expect + 4096);
        let mut consumed = 0;
        loop {
            // decompress_vec only writes into spare capacity; it never grows the Vec.
            if out.len() == out.capacity() {
                out.reserve(expect.max(4096));
            }
            let (in0, out0) = (self.zlib.total_in(), self.zlib.total_out());
            self.zlib.decompress_vec(
                &input[consumed..],
                &mut out,
                flate2::FlushDecompress::None,
            )?;
            consumed += (self.zlib.total_in() - in0) as usize;
            // No input taken and no output produced means the stream is drained.
            if self.zlib.total_in() == in0 && self.zlib.total_out() == out0 {
                return Ok(out);
            }
        }
    }

    fn zrle(
        &mut self,
        r: &mut impl Read,
        s: &mut Screen,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    ) -> Res<()> {
        let n = u32r(r)? as usize;
        let compressed = blob(r, n)?;
        let data = self.inflate(&compressed, w * h * 3)?;
        let mut d: &[u8] = &data;
        // 64x64 tiles in raster order; the right and bottom edges may be smaller.
        for ty in (0..h).step_by(64) {
            for tx in (0..w).step_by(64) {
                let tw = (w - tx).min(64);
                let th = (h - ty).min(64);
                zrle_tile(&mut d, s, x + tx, y + ty, tw, th)?;
            }
        }
        Ok(())
    }
}

/// One ZRLE tile. The leading byte says how it is encoded: bit 7 means RLE, and the
/// low 7 bits are the palette size (0 meaning no palette).
fn zrle_tile(r: &mut impl Read, s: &mut Screen, x: usize, y: usize, w: usize, h: usize) -> Res<()> {
    let sub = u8r(r)?;
    let rle = sub & 0x80 != 0;
    let palette_size = (sub & 0x7f) as usize;
    let mut put = |i: usize, c: u32| s.px[(y + i / w) * s.w + x + i % w] = c;

    match (rle, palette_size) {
        // Raw tile.
        (false, 0) => {
            for i in 0..w * h {
                put(i, cpixel(r)?);
            }
        }
        // Solid tile: a single colour.
        (false, 1) => {
            let c = cpixel(r)?;
            for i in 0..w * h {
                put(i, c);
            }
        }
        // Packed palette: indices bit-packed MSB-first, each row padded to a byte.
        (false, 2..=16) => {
            let pal = read_palette(r, palette_size)?;
            let bits = match palette_size {
                2 => 1,
                3..=4 => 2,
                _ => 4,
            };
            for row in 0..h {
                let line = blob(r, (w * bits).div_ceil(8))?;
                for col in 0..w {
                    let bit = col * bits;
                    let idx = (line[bit / 8] >> (8 - bits - bit % 8)) & ((1 << bits) - 1);
                    let c = *pal
                        .get(idx as usize)
                        .ok_or("ZRLE palette index out of range")?;
                    put(row * w + col, c);
                }
            }
        }
        // Plain RLE: colour then run length, runs flow across rows.
        (true, 0) => {
            let mut i = 0;
            while i < w * h {
                let c = cpixel(r)?;
                let n = run_len(r)?;
                if i + n > w * h {
                    return Err("ZRLE run overruns its tile".into());
                }
                for _ in 0..n {
                    put(i, c);
                    i += 1;
                }
            }
        }
        // Palette RLE: an index byte, and the high bit marks a run rather than one pixel.
        (true, 2..=127) => {
            let pal = read_palette(r, palette_size)?;
            let mut i = 0;
            while i < w * h {
                let b = u8r(r)?;
                let c = *pal
                    .get((b & 0x7f) as usize)
                    .ok_or("ZRLE palette index out of range")?;
                let n = if b & 0x80 != 0 { run_len(r)? } else { 1 };
                if i + n > w * h {
                    return Err("ZRLE run overruns its tile".into());
                }
                for _ in 0..n {
                    put(i, c);
                    i += 1;
                }
            }
        }
        _ => return Err(format!("invalid ZRLE subencoding {sub}").into()),
    }
    Ok(())
}

fn read_palette(r: &mut impl Read, n: usize) -> Res<Vec<u32>> {
    (0..n).map(|_| cpixel(r)).collect()
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
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
        let md5: [u8; 16] = Md5::digest(b"abc").into();
        assert_eq!(
            md5,
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
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
        let mut s = Screen {
            w: 2,
            h: 2,
            px: vec![0; 4],
        };
        #[rustfmt::skip]
        let bytes: [u8; 16] = [
            0, 1,  0, 1,          // x=1, y=1
            0, 1,  0, 1,          // w=1, h=1
            0, 0, 0, 0,           // encoding = Raw
            0xAA, 0xBB, 0xCC, 0,  // one pixel: B, G, R, pad
        ];
        Decoder::new().rect(&mut &bytes[..], &mut s).unwrap();
        assert_eq!(s.px, vec![0, 0, 0, 0x00CC_BBAA]);
    }

    /// B, G, R - a CPIXEL, which is a pixel minus the unused fourth byte.
    fn cp(c: u32) -> [u8; 3] {
        [c as u8, (c >> 8) as u8, (c >> 16) as u8]
    }

    /// Run `payload` through a zlib stream and wrap it as ZRLE rectangles. Returns
    /// one encoded rectangle per payload, all sharing a single zlib stream, which is
    /// what a real server does.
    fn zrle_rects(dims: (usize, usize), payloads: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut c = flate2::Compress::new(flate2::Compression::default(), true);
        let mut out = Vec::new();
        for payload in payloads {
            // Capacity is ample for these small payloads, so each step needs one call.
            // Note the flush must happen exactly once: calling Sync repeatedly emits a
            // fresh sync marker every time and never reports "done".
            let mut z = Vec::with_capacity(payload.len() * 2 + 1024);
            let mut consumed = 0;
            while consumed < payload.len() {
                let in0 = c.total_in();
                c.compress_vec(&payload[consumed..], &mut z, flate2::FlushCompress::None)
                    .unwrap();
                consumed += (c.total_in() - in0) as usize;
                assert!(c.total_in() > in0, "compressor stalled on input");
            }
            c.compress_vec(&[], &mut z, flate2::FlushCompress::Sync)
                .unwrap();
            assert!(
                z.len() < z.capacity(),
                "flush filled the buffer; reserve more"
            );
            let mut m = Vec::new();
            m.extend_from_slice(&0u16.to_be_bytes()); // x
            m.extend_from_slice(&0u16.to_be_bytes()); // y
            m.extend_from_slice(&(dims.0 as u16).to_be_bytes());
            m.extend_from_slice(&(dims.1 as u16).to_be_bytes());
            m.extend_from_slice(&16i32.to_be_bytes()); // ZRLE
            m.extend_from_slice(&(z.len() as u32).to_be_bytes());
            m.extend_from_slice(&z);
            out.push(m);
        }
        out
    }

    fn decode_one(payload: Vec<u8>) -> Vec<u32> {
        let mut s = Screen {
            w: 2,
            h: 2,
            px: vec![0; 4],
        };
        let rects = zrle_rects((2, 2), &[payload]);
        Decoder::new().rect(&mut &rects[0][..], &mut s).unwrap();
        s.px
    }

    const A: u32 = 0x00AA_BBCC;
    const B: u32 = 0x0011_2233;

    #[test]
    fn zrle_solid_and_raw_tiles() {
        // Subencoding 1: one colour for the whole tile.
        let mut solid = vec![1u8];
        solid.extend_from_slice(&cp(A));
        assert_eq!(decode_one(solid), vec![A; 4]);

        // Subencoding 0: every pixel spelled out.
        let mut raw = vec![0u8];
        for c in [A, B, B, A] {
            raw.extend_from_slice(&cp(c));
        }
        assert_eq!(decode_one(raw), vec![A, B, B, A]);
    }

    #[test]
    fn zrle_packed_palette_unpacks_msb_first() {
        // Two colours => 1 bit per index, each row padded to a whole byte.
        let mut t = vec![2u8];
        t.extend_from_slice(&cp(A));
        t.extend_from_slice(&cp(B));
        t.push(0b0100_0000); // row 0: A then B
        t.push(0b1000_0000); // row 1: B then A
        assert_eq!(decode_one(t), vec![A, B, B, A]);
    }

    #[test]
    fn zrle_rle_tiles_run_across_rows() {
        // Plain RLE: colour, then a length byte (length is one more than the sum).
        let mut plain = vec![128u8];
        plain.extend_from_slice(&cp(A));
        plain.push(1); // run of 2
        plain.extend_from_slice(&cp(B));
        plain.push(1); // run of 2
        assert_eq!(decode_one(plain), vec![A, A, B, B]);

        // Palette RLE: index byte, high bit means a run follows.
        let mut pal = vec![130u8];
        pal.extend_from_slice(&cp(A));
        pal.extend_from_slice(&cp(B));
        pal.extend_from_slice(&[0x80, 1]); // palette[0] x2
        pal.extend_from_slice(&[0x81, 1]); // palette[1] x2
        assert_eq!(decode_one(pal), vec![A, A, B, B]);
    }

    #[test]
    fn zrle_run_overrunning_its_tile_is_rejected() {
        let mut t = vec![128u8];
        t.extend_from_slice(&cp(A));
        t.push(200); // run of 201 into a 4-pixel tile
        let rects = zrle_rects((2, 2), &[t]);
        let mut s = Screen {
            w: 2,
            h: 2,
            px: vec![0; 4],
        };
        assert!(Decoder::new().rect(&mut &rects[0][..], &mut s).is_err());
    }

    /// ZRLE's zlib stream spans the connection. A decoder that resets it per
    /// rectangle decodes the first one and then produces garbage, so decode two
    /// rectangles from one stream and check the second is still right.
    #[test]
    fn zrle_zlib_stream_persists_across_rectangles() {
        let mut first = vec![1u8];
        first.extend_from_slice(&cp(A));
        let mut second = vec![1u8];
        second.extend_from_slice(&cp(B));

        let rects = zrle_rects((2, 2), &[first, second]);
        let mut s = Screen {
            w: 2,
            h: 2,
            px: vec![0; 4],
        };
        let mut d = Decoder::new();
        d.rect(&mut &rects[0][..], &mut s).unwrap();
        assert_eq!(s.px, vec![A; 4]);
        d.rect(&mut &rects[1][..], &mut s).unwrap();
        assert_eq!(s.px, vec![B; 4]);
    }

    /// Dragging a window makes the source and destination overlap. Copying in place
    /// front-to-back would smear the first pixel across the whole run.
    #[test]
    fn copy_rect_handles_overlapping_source_and_destination() {
        let mut s = Screen {
            w: 4,
            h: 1,
            px: vec![1, 2, 3, 4],
        };
        #[rustfmt::skip]
        let bytes: [u8; 16] = [
            0, 1,  0, 0,   // dst x=1, y=0
            0, 3,  0, 1,   // w=3, h=1
            0, 0, 0, 1,    // encoding = CopyRect
            0, 0,  0, 0,   // src x=0, y=0
        ];
        Decoder::new().rect(&mut &bytes[..], &mut s).unwrap();
        assert_eq!(s.px, vec![1, 1, 2, 3]);
    }

    #[test]
    fn copy_rect_with_offscreen_source_is_rejected() {
        let mut s = Screen {
            w: 4,
            h: 1,
            px: vec![1, 2, 3, 4],
        };
        let bytes: [u8; 16] = [0, 0, 0, 0, 0, 3, 0, 1, 0, 0, 0, 1, 0, 2, 0, 0];
        assert!(Decoder::new().rect(&mut &bytes[..], &mut s).is_err());
    }

    #[test]
    fn rect_outside_the_framebuffer_is_rejected() {
        let mut s = Screen {
            w: 2,
            h: 2,
            px: vec![0; 4],
        };
        let bytes: [u8; 12] = [0, 1, 0, 1, 0, 4, 0, 4, 0, 0, 0, 0];
        assert!(Decoder::new().rect(&mut &bytes[..], &mut s).is_err());
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
    fn clipboard_text_converts_to_and_from_latin1() {
        // Header is type 6, three padding bytes, then a big-endian length.
        assert_eq!(cut_text_msg("hi"), vec![6, 0, 0, 0, 0, 0, 0, 2, b'h', b'i']);
        // Windows CRLF must go out as bare LF - RFB has no CR.
        assert_eq!(cut_text_msg("a\r\nb")[8..], [b'a', b'\n', b'b']);
        // Outside Latin-1 becomes '?' rather than mangling the byte count.
        assert_eq!(
            cut_text_msg("caf\u{e9} \u{4e2d}")[8..],
            [b'c', b'a', b'f', 0xe9, b' ', b'?']
        );
        // A 2-byte char must not be counted as 2 bytes in the length field.
        assert_eq!(
            u32::from_be_bytes(cut_text_msg("\u{4e2d}")[4..8].try_into().unwrap()),
            1
        );

        // Coming back the other way, LF regains its CR so Windows apps paste right.
        assert_eq!(from_latin1(b"a\nb"), "a\r\nb");
        assert_eq!(from_latin1(&[0xe9]), "\u{e9}");
        assert_eq!(from_latin1(b""), "");
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
