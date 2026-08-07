//! vncfree - a free VNC (RFB) client for Windows.
//!
//! Live window, keyboard and mouse, shared clipboard, automatic reconnect. Speaks
//! RFB 3.8 with Raw, CopyRect and ZRLE encodings, and authenticates with either
//! classic VNC auth or Apple's Diffie-Hellman scheme for macOS.
//!
//! Run with no arguments and it asks where to connect. Given an address it connects
//! straight away, and a second argument is a path for a headless one-frame PPM dump.
//! Settings come from the environment: VNC_USERNAME, VNC_PASSWORD, VNC_VIEW_ONLY,
//! VNC_ENCODING, VNC_DEBUG.

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
type Writer = Arc<Mutex<Option<vncfree::wire::WireWrite>>>;

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

/// The VeNCrypt sub-negotiation, up to the point where TLS takes over. Returns the two
/// encrypted halves and the server certificate's fingerprint.
///
/// Only the X509 subtypes are usable here. VeNCrypt's plain TLS types authenticate with
/// anonymous Diffie-Hellman, which offers no defence against someone sitting in the
/// middle and which rustls does not implement. A server offering only those is refused
/// with an explanation rather than silently downgraded.
fn vencrypt(
    tcp: &mut TcpStream,
) -> Res<(vncfree::wire::WireRead, vncfree::wire::WireWrite, String)> {
    const X509_VNC: u32 = 261;

    let theirs = rd::<2>(tcp)?;
    if theirs[0] != 0 || theirs[1] < 2 {
        return Err(format!(
            "server speaks VeNCrypt {}.{}, and vncfree needs 0.2",
            theirs[0], theirs[1]
        )
        .into());
    }
    tcp.write_all(&[0, 2])?;
    if u8r(tcp)? != 0 {
        return Err("server rejected VeNCrypt 0.2".into());
    }

    let n = u8r(tcp)? as usize;
    let list = blob(tcp, n * 4)?;
    let subtypes: Vec<u32> = list
        .chunks(4)
        .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
        .collect();
    if debug() {
        eprintln!("[debug] VeNCrypt subtypes offered {subtypes:?}");
    }
    if !subtypes.contains(&X509_VNC) {
        return Err(format!(
            "server offers VeNCrypt subtypes {subtypes:?}, none of which vncfree can \
             use. It needs X509Vnc (261): the TLS* subtypes authenticate with anonymous \
             Diffie-Hellman, which cannot detect anyone sitting in the middle of the \
             connection and which no current TLS library will do."
        )
        .into());
    }
    tcp.write_all(&X509_VNC.to_be_bytes())?;
    // Unlike every other acknowledgement in RFB, *one* means success here.
    if u8r(tcp)? != 1 {
        return Err("server refused the X509Vnc subtype it had just offered".into());
    }

    vncfree::wire::client(tcp.try_clone()?)
}

/// Everything needed to open the connection again after it drops.
struct Target {
    addr: String,
    user: String,
    pass: String,
}

struct Vnc {
    r: BufReader<vncfree::wire::WireRead>,
    w: Writer,
    screen: Screen,
    name: String,
    dec: Decoder,
    clip: Clip,
    /// Text the server sent us, waiting to go onto the Windows clipboard. The
    /// clipboard handle itself is not held here because this struct moves between
    /// threads on every reconnect.
    pending_paste: Option<String>,
    /// Ask for the next frame as soon as one starts arriving, rather than after it
    /// has been decoded. Off for the one-shot PPM grab, which wants exactly one.
    pipeline: bool,
    /// Regions the last update actually touched, so only those need copying to the
    /// thread that draws. Copying the whole framebuffer is 8MB at 1080p and 33MB at
    /// 4K, every frame, most of it unchanged.
    dirty: Vec<(usize, usize, usize, usize)>,
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
        let mut tcp = TcpStream::connect_timeout(&resolved, std::time::Duration::from_secs(10))
            .map_err(|e| format!("could not connect to {addr}: {e}"))?;
        tcp.set_nodelay(true)?;

        // Everything up to the security type is read straight off the socket rather
        // than through a BufReader. A BufReader takes whatever has arrived, and if the
        // security handshake is about to hand the connection over to TLS, bytes it read
        // ahead into its own buffer are bytes the TLS session never sees.
        //
        // --- version handshake ---
        let ver = String::from_utf8_lossy(&rd::<12>(&mut tcp)?)
            .trim_end()
            .to_string();
        // Apple's Screen Sharing announces "RFB 003.889". Replying 003.008 makes it
        // fall back to being a standard 3.8 server, so anything at or above 8 is
        // answered with 8.
        let minor: u32 = ver
            .strip_prefix("RFB 003.")
            .and_then(|m| m.parse().ok())
            .ok_or_else(|| format!("not an RFB 3.x server: {ver:?}"))?;
        // The reply is a choice, not an acknowledgement, and it may not exceed what the
        // server offered: answering a 3.3 server with 3.8 is not a negotiation, it is a
        // protocol error. Anything below 7 is 3.3, which is the floor.
        let speak = match minor {
            0..=6 => 3,
            7 => 7,
            _ => 8,
        };
        tcp.write_all(format!("RFB 003.{speak:03}\n").as_bytes())?;

        // --- security handshake ---
        let types = if speak == 3 {
            // 3.3 has no negotiation at all: the server decides and says so in one
            // word, and the client's only options are to go along with it or hang up.
            match u32r(&mut tcp)? {
                0 => return Err(format!("server refused connection: {}", text(&mut tcp)?).into()),
                t @ (1 | 2) => vec![t as u8],
                t => {
                    return Err(format!(
                        "server chose security type {t}, which RFB 3.3 does not define"
                    )
                    .into())
                }
            }
        } else {
            let n = u8r(&mut tcp)? as usize;
            if n == 0 {
                return Err(format!("server refused connection: {}", text(&mut tcp)?).into());
            }
            blob(&mut tcp, n)?
        };
        if debug() {
            eprintln!(
                "[debug] server version {ver:?}, answering 003.{speak:03}, \
                 security types offered {types:?}"
            );
        }
        let want_tls = env::var("VNC_TLS").unwrap_or_default() == "require";
        // VeNCrypt first: it is the only one of these that encrypts anything.
        let chosen = if types.contains(&19) {
            19 // VeNCrypt: TLS, then one of the others inside it
        } else if want_tls {
            return Err(format!(
                "VNC_TLS=require is set and this server does not offer VeNCrypt; it \
                 offered security types {types:?}"
            )
            .into());
        } else if types.contains(&1) {
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
        // 3.3 stated the type rather than offering one, so there is nothing to send
        // back; a byte here would be read as the start of the next message.
        if speak > 3 {
            tcp.write_all(&[chosen])?;
        }

        // VeNCrypt hands the connection to TLS and then runs one of the ordinary
        // security types inside it, so `chosen` becomes whatever that turns out to be.
        let (reader, mut w, chosen) = if chosen == 19 {
            let (r, w, print) = vencrypt(&mut tcp)?;
            eprintln!("session encrypted; certificate {print}");
            // Refuses the connection if this host has shown a different certificate
            // before, so an interception that starts after the first connection does
            // not go unnoticed.
            vncfree::wire::check_known(addr, &print)?;
            (r, w, 2)
        } else {
            let (r, w) = vncfree::wire::plain(tcp)?;
            (r, w, chosen)
        };
        let mut r = BufReader::new(reader);

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
        // Before 3.8, a security type of None is followed by nothing at all - the
        // initialisation phase starts immediately. Reading a SecurityResult that is
        // never coming hangs the connection on a server that is waiting for us.
        let expect_result = chosen != 1 || speak >= 8;
        if expect_result && u32r(&mut r)? != 0 {
            // The reason string arrived with 3.8. Older servers just hang up, so
            // asking for one blocks until the socket closes.
            let why = if speak >= 8 {
                text(&mut r)?
            } else {
                format!("the server gave no reason (RFB 3.{speak} has nowhere to put one)")
            };
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
        //
        // Asking for exactly one of them is how "is it my decoder or the server?" gets
        // answered, and how one encoding is checked against another: grab the same
        // still screen twice and the two files must be byte-identical.
        let encodings: Vec<i32> = match env::var("VNC_ENCODING").unwrap_or_default().as_str() {
            "raw" => {
                eprintln!("VNC_ENCODING=raw: requesting Raw only");
                vec![0]
            }
            "tight" => {
                eprintln!("VNC_ENCODING=tight: requesting Tight only");
                vec![7, 0]
            }
            "zrle" => {
                eprintln!("VNC_ENCODING=zrle: requesting ZRLE only");
                vec![16, 0]
            }
            "" => {
                // -223 is DesktopSize: not an encoding but a way for the server to say
                // the screen resolution changed. Without asking for it, a server that
                // changes resolution has no way to tell us and the session is stuck at
                // the old size.
                //
                // ZRLE before Tight on purpose. A server offering both - TigerVNC does
                // - keeps giving us lossless ZRLE, and Tight is there for the servers
                // that do not speak ZRLE at all, where the fallback would otherwise be
                // Raw. Tight is the only thing here that can arrive lossy, and only
                // because a server chose to send JPEG.
                vec![16, 7, 1, 0, -223] // ZRLE, Tight, CopyRect, Raw, DesktopSize
            }
            other => {
                return Err(format!("VNC_ENCODING={other:?}: expected raw, tight or zrle").into())
            }
        };

        // Asking for a quality level tells a Tight server it may send JPEG, which is
        // lossy and much smaller. Unset means lossless, because a remote desktop is
        // mostly text and JPEG makes a mess of text. The levels are pseudo-encodings
        // -32 (worst) to -23 (best).
        let mut encodings = encodings;
        if let Ok(q) = env::var("VNC_QUALITY") {
            let level: i32 = q
                .parse()
                .ok()
                .filter(|l| (0..=9).contains(l))
                .ok_or_else(|| format!("VNC_QUALITY={q:?}: expected 0 to 9"))?;
            eprintln!("VNC_QUALITY={level}: allowing the server to send lossy JPEG");
            encodings.push(-32 + level);
        }
        w.write_all(&[2, 0])?;
        w.write_all(&(encodings.len() as u16).to_be_bytes())?;
        for e in &encodings {
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
            pipeline: false,
            dirty: Vec::new(),
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
                // Ask for the next frame *now*, before decoding this one. Waiting
                // until the update is decoded and copied leaves the server idle for
                // all of that time, so every frame costs a round trip plus our own
                // work rather than overlapping the two.
                if self.pipeline {
                    self.request(true)?;
                }
                self.dirty.clear();
                for _ in 0..rects {
                    let touched = self.dec.rect(&mut self.r, &mut self.screen)?;
                    self.dirty.push(touched);
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
            other => {
                // A message whose length we do not know cannot be skipped, so this
                // ends the session either way. Dump what follows first: an
                // unrecognised type is exactly how a proprietary extension announces
                // itself, and these bytes are the only record of it.
                if debug() {
                    let mut peek = [0u8; 64];
                    let n = std::io::Read::read(&mut self.r, &mut peek).unwrap_or(0);
                    eprintln!(
                        "[debug] unknown server message type {other}, next {n} bytes: {:02x?}",
                        &peek[..n]
                    );
                }
                Err(format!("unexpected server message type {other}").into())
            }
        }
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

/// Longest clipboard this will type. At roughly a hundred characters a second a
/// runaway paste is worse than no paste, and a clipboard this size is not something
/// anyone meant to send through a keyboard.
const MAX_TYPED: usize = 4000;

/// Turn text into the keys needed to type it: each entry is a keysym and whether
/// shift must be held for it.
///
/// This exists because macOS does not do clipboard over VNC at all - see
/// docs/macos.md - so the only way to get text onto a Mac is to type it.
///
/// Shift is stated explicitly rather than left to the server. RFB says a keysym *is*
/// the character, but a server that maps 'A' straight onto the A key without holding
/// shift produces a lowercase 'a' - which is exactly what vncfree-server does, and
/// probably not alone.
fn typed_keys(text: &str) -> Vec<(u32, bool)> {
    text.chars()
        .filter(|c| *c != '\r') // CRLF arrives as one Return, not two
        .map(|c| match c {
            '\n' => (0xff0d, false), // Return
            '\t' => (0xff09, false), // Tab
            'A'..='Z' => (c as u32, true),
            // Anything else goes as its own keysym. Servers that cannot map it to a
            // key generally fall back to injecting the character directly, which
            // handles punctuation and accents without a layout table here.
            c if (c as u32) < 256 => (c as u32, false),
            c => (0x0100_0000 + c as u32, false),
        })
        .collect()
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
    /// What the keyboard layout made of the keys pressed this frame.
    typed: Typed,
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
            typed: Typed::default(),
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
        drop(f);
        dirty.store(true, Ordering::Relaxed);
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
    // Characters land here as the window pumps its messages, with the keyboard layout
    // already applied by Windows.
    window.set_input_callback(Box::new(input.typed.clone()));

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
/// A Tight pixel. Three bytes, and - unlike ZRLE's CPIXEL, which keeps the byte order
/// of the pixel format - the spec states these are red, green and blue in that order.
/// Reusing the CPIXEL reader here swaps every red and blue on screen.
fn tpixel(r: &mut impl Read) -> Res<u32> {
    let b = rd::<3>(r)?;
    Ok((b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32)
}

/// Tight's own length format: seven bits per byte, low group first, with the top bit
/// meaning another byte follows. Three bytes at most.
fn compact_len(r: &mut impl Read) -> Res<usize> {
    let b0 = u8r(r)? as usize;
    let mut len = b0 & 0x7f;
    if b0 & 0x80 != 0 {
        let b1 = u8r(r)? as usize;
        len |= (b1 & 0x7f) << 7;
        if b1 & 0x80 != 0 {
            len |= (u8r(r)? as usize) << 14;
        }
    }
    Ok(len)
}

/// Pull the next block out of a zlib stream that spans the whole connection.
fn inflate(z: &mut flate2::Decompress, input: &[u8], expect: usize) -> Res<Vec<u8>> {
    let mut out = Vec::with_capacity(expect + 4096);
    let mut consumed = 0;
    loop {
        // decompress_vec only writes into spare capacity; it never grows the Vec.
        if out.len() == out.capacity() {
            out.reserve(expect.max(4096));
        }
        let (in0, out0) = (z.total_in(), z.total_out());
        z.decompress_vec(&input[consumed..], &mut out, flate2::FlushDecompress::None)?;
        consumed += (z.total_in() - in0) as usize;
        // No input taken and no output produced means the stream is drained.
        if z.total_in() == in0 && z.total_out() == out0 {
            return Ok(out);
        }
    }
}

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
    /// Tight has four of them, also spanning the connection, and the server picks one
    /// per rectangle and restarts whichever it likes. Four rather than one so that
    /// different kinds of content each keep a dictionary suited to them.
    tight: [flate2::Decompress; 4],
}

impl Decoder {
    fn new() -> Decoder {
        Decoder {
            zlib: flate2::Decompress::new(true),
            tight: std::array::from_fn(|_| flate2::Decompress::new(true)),
        }
    }

    /// Decode one rectangle, returning the region of the framebuffer it changed.
    fn rect(&mut self, r: &mut impl Read, s: &mut Screen) -> Res<(usize, usize, usize, usize)> {
        let x = u16r(r)? as usize;
        let y = u16r(r)? as usize;
        let w = u16r(r)? as usize;
        let h = u16r(r)? as usize;
        let enc = i32r(r)?;
        // DesktopSize is not a picture: the rectangle header carries the screen's new
        // size and there is no body. It has to be handled before the bounds check,
        // since a screen that grew is by definition outside the old framebuffer.
        if enc == -223 {
            if debug() {
                eprintln!("[debug] remote resolution is now {w}x{h}");
            }
            s.w = w;
            s.h = h;
            s.px = vec![0; w * h];
            return Ok((0, 0, w, h));
        }
        if x + w > s.w || y + h > s.h {
            return Err(format!("rect {x},{y} {w}x{h} outside {}x{} framebuffer", s.w, s.h).into());
        }
        self.decode(r, s, x, y, w, h, enc)?;
        Ok((x, y, w, h))
    }

    #[allow(clippy::too_many_arguments)]
    fn decode(
        &mut self,
        r: &mut impl Read,
        s: &mut Screen,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        enc: i32,
    ) -> Res<()> {
        match enc {
            0 => self.raw(r, s, x, y, w, h),
            1 => self.copy_rect(r, s, x, y, w, h),
            7 => self.tight(r, s, x, y, w, h),
            16 => self.zrle(r, s, x, y, w, h),
            _ => {
                // Anything else carries a body whose length only that encoding
                // defines, so the stream cannot be resynchronised. Record it first.
                if debug() {
                    let mut peek = [0u8; 64];
                    let n = std::io::Read::read(r, &mut peek).unwrap_or(0);
                    eprintln!(
                        "[debug] encoding {enc}: rect {x},{y} {w}x{h}, next {n} bytes: {:02x?}",
                        &peek[..n]
                    );
                }
                Err(format!("encoding {enc} not implemented").into())
            }
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
    /// Tight (encoding 7), which is what most third-party servers reach for first.
    ///
    /// The rectangle opens with one control byte: the low nibble restarts any of the
    /// four zlib streams, and the high nibble says what follows.
    fn tight(
        &mut self,
        r: &mut impl Read,
        s: &mut Screen,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    ) -> Res<()> {
        let ctl = u8r(r)?;
        for (i, z) in self.tight.iter_mut().enumerate() {
            if ctl & (1 << i) != 0 {
                z.reset(true);
            }
        }
        if debug() {
            // Which form a server actually chose is otherwise invisible, and a decoder
            // can look correct simply by never being handed the hard cases.
            let what = match ctl >> 4 {
                0x08 => "fill".to_string(),
                0x09 => "jpeg".to_string(),
                t if t >= 0x0a => format!("bad type {t:#x}"),
                t if t & 0x04 == 0 => format!("basic copy, stream {}", t & 3),
                t => format!("basic filtered, stream {}", t & 3),
            };
            eprintln!("[debug] tight {w}x{h}: {what}");
        }
        match ctl >> 4 {
            // Fill: one colour for the whole rectangle, and no compression involved.
            0x08 => {
                let c = tpixel(r)?;
                for row in 0..h {
                    let o = (y + row) * s.w + x;
                    s.px[o..o + w].fill(c);
                }
                Ok(())
            }
            0x09 => self.tight_jpeg(r, s, x, y, w, h),
            // 0x0A is TightPng, which is a different encoding number and not this one.
            t @ 0x0a.. => {
                Err(format!("tight compression type {t:#x} is not part of the encoding").into())
            }
            t => {
                let stream = (t & 0x03) as usize;
                // Without the flag the filter is Copy, and no byte is sent for it.
                let filter = if t & 0x04 != 0 { u8r(r)? } else { 0 };
                self.tight_basic(r, s, x, y, w, h, stream, filter)
            }
        }
    }

    /// The compressed forms: raw pixels, a palette, or a gradient prediction.
    #[allow(clippy::too_many_arguments)]
    fn tight_basic(
        &mut self,
        r: &mut impl Read,
        s: &mut Screen,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        stream: usize,
        filter: u8,
    ) -> Res<()> {
        // The palette itself is *not* compressed. It sits between the filter byte and
        // the compressed block, so it has to be read before the length is known.
        let palette = match filter {
            1 => {
                let n = u8r(r)? as usize + 1;
                let mut p = Vec::with_capacity(n);
                for _ in 0..n {
                    p.push(tpixel(r)?);
                }
                Some(p)
            }
            0 | 2 => None,
            f => {
                return Err(
                    format!("tight filter {f} is not one of copy, palette or gradient").into(),
                )
            }
        };

        let expect = match &palette {
            // Two colours are packed one bit per pixel, each row padded to a byte.
            Some(p) if p.len() == 2 => w.div_ceil(8) * h,
            Some(_) => w * h,
            None => w * h * 3,
        };

        // Below a dozen bytes the server does not bother compressing, and sends no
        // length either - the rectangle's size already says how much there is.
        let data = if expect < 12 {
            blob(r, expect)?
        } else {
            let n = compact_len(r)?;
            let z = blob(r, n)?;
            inflate(&mut self.tight[stream], &z, expect)?
        };
        if data.len() < expect {
            return Err(format!("tight rect wanted {expect} bytes, got {}", data.len()).into());
        }

        match &palette {
            Some(pal) if pal.len() == 2 => {
                let stride = w.div_ceil(8);
                for row in 0..h {
                    for col in 0..w {
                        let bit = data[row * stride + col / 8] >> (7 - col % 8) & 1;
                        s.px[(y + row) * s.w + x + col] = pal[bit as usize];
                    }
                }
            }
            Some(pal) => {
                for row in 0..h {
                    for col in 0..w {
                        let i = data[row * w + col] as usize;
                        let c = pal
                            .get(i)
                            .ok_or_else(|| format!("tight palette index {i} of {}", pal.len()))?;
                        s.px[(y + row) * s.w + x + col] = *c;
                    }
                }
            }
            // Gradient: each component is predicted from the pixels to the left, above
            // and above-left, and what arrives is the difference from that prediction.
            None if filter == 2 => {
                let (mut prev, mut cur) = (vec![0u8; w * 3], vec![0u8; w * 3]);
                for row in 0..h {
                    for col in 0..w {
                        for c in 0..3 {
                            let left = if col > 0 {
                                cur[(col - 1) * 3 + c] as i32
                            } else {
                                0
                            };
                            let up = prev[col * 3 + c] as i32;
                            let upleft = if col > 0 {
                                prev[(col - 1) * 3 + c] as i32
                            } else {
                                0
                            };
                            let guess = (left + up - upleft).clamp(0, 255);
                            // Wrapping on purpose: the difference was taken mod 256.
                            cur[col * 3 + c] = (data[(row * w + col) * 3 + c] as i32 + guess) as u8;
                        }
                        s.px[(y + row) * s.w + x + col] = (cur[col * 3] as u32) << 16
                            | (cur[col * 3 + 1] as u32) << 8
                            | cur[col * 3 + 2] as u32;
                    }
                    std::mem::swap(&mut prev, &mut cur);
                }
            }
            // Copy: the pixels as they are.
            None => {
                for row in 0..h {
                    for col in 0..w {
                        let p = (row * w + col) * 3;
                        s.px[(y + row) * s.w + x + col] =
                            (data[p] as u32) << 16 | (data[p + 1] as u32) << 8 | data[p + 2] as u32;
                    }
                }
            }
        }
        Ok(())
    }

    /// A JPEG image covering the rectangle. This is the one lossy thing vncfree will
    /// display, and only ever because a server chose to send it.
    fn tight_jpeg(
        &mut self,
        r: &mut impl Read,
        s: &mut Screen,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    ) -> Res<()> {
        let n = compact_len(r)?;
        let data = blob(r, n)?;
        let mut dec = jpeg_decoder::Decoder::new(&data[..]);
        let px = dec.decode()?;
        let info = dec.info().ok_or("a JPEG rectangle with no header")?;
        if info.width as usize != w || info.height as usize != h {
            return Err(format!(
                "JPEG is {}x{} but the rectangle is {w}x{h}",
                info.width, info.height
            )
            .into());
        }
        // Servers send colour, but a greyscale JPEG is legal and cheap to allow for.
        let step = match info.pixel_format {
            jpeg_decoder::PixelFormat::RGB24 => 3,
            jpeg_decoder::PixelFormat::L8 => 1,
            f => return Err(format!("JPEG pixel format {f:?} is not supported").into()),
        };
        for row in 0..h {
            for col in 0..w {
                let p = (row * w + col) * step;
                let (r8, g8, b8) = if step == 3 {
                    (px[p], px[p + 1], px[p + 2])
                } else {
                    (px[p], px[p], px[p])
                };
                s.px[(y + row) * s.w + x + col] = (r8 as u32) << 16 | (g8 as u32) << 8 | b8 as u32;
            }
        }
        Ok(())
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
        let data = inflate(&mut self.zlib, &compressed, w * h * 3)?;
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

    /// DesktopSize has to be acted on before the bounds check, because a screen that
    /// grew is by definition outside the framebuffer it is replacing.
    #[test]
    fn desktop_size_resizes_the_framebuffer() {
        let mut s = Screen {
            w: 2,
            h: 2,
            px: vec![9; 4],
        };
        #[rustfmt::skip]
        let bytes: [u8; 12] = [
            0, 0,  0, 0,          // x, y - ignored
            0, 4,  0, 3,          // the new size, 4x3
            0xff, 0xff, 0xff, 0x21, // encoding -223, and no body at all
        ];
        let touched = Decoder::new().rect(&mut &bytes[..], &mut s).unwrap();
        assert_eq!((s.w, s.h), (4, 3), "framebuffer follows the screen");
        assert_eq!(s.px.len(), 12);
        assert!(s.px.iter().all(|&p| p == 0), "and starts blank");
        assert_eq!(touched, (0, 0, 4, 3), "the whole of it is now dirty");
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

    /// Build the 12-byte rectangle header Tight bodies hang off.
    fn tight_rect(w: usize, h: usize, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0u16.to_be_bytes()); // x
        v.extend_from_slice(&0u16.to_be_bytes()); // y
        v.extend_from_slice(&(w as u16).to_be_bytes());
        v.extend_from_slice(&(h as u16).to_be_bytes());
        v.extend_from_slice(&7i32.to_be_bytes()); // Tight
        v.extend_from_slice(body);
        v
    }

    fn blank(w: usize, h: usize) -> Screen {
        Screen {
            w,
            h,
            px: vec![0; w * h],
        }
    }

    /// Tight's length header, as a server would write it.
    fn compact(n: usize) -> Vec<u8> {
        if n < 0x80 {
            vec![n as u8]
        } else if n < 0x4000 {
            vec![(n & 0x7f) as u8 | 0x80, (n >> 7) as u8]
        } else {
            vec![
                (n & 0x7f) as u8 | 0x80,
                ((n >> 7) & 0x7f) as u8 | 0x80,
                (n >> 14) as u8,
            ]
        }
    }

    /// One block of a persistent zlib stream, flushed so the far end can read it back
    /// without waiting for more.
    fn deflate(z: &mut flate2::Compress, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 1024);
        z.compress_vec(data, &mut out, flate2::FlushCompress::Sync)
            .unwrap();
        out
    }

    /// A whole rectangle in one colour, and the byte order trap: TPIXEL is red, green,
    /// blue, where ZRLE's CPIXEL in the very same decoder is blue, green, red. Reusing
    /// the wrong one swaps every red and blue on screen and still decodes cleanly.
    #[test]
    fn tight_fill_is_one_colour_in_rgb_order() {
        let mut s = blank(3, 2);
        let body = [0x80, 0x11, 0x22, 0x33];
        let touched = Decoder::new()
            .rect(&mut &tight_rect(3, 2, &body)[..], &mut s)
            .unwrap();
        assert_eq!(touched, (0, 0, 3, 2));
        assert!(s.px.iter().all(|&p| p == 0x0011_2233), "{:06x?}", s.px);
    }

    /// Under twelve bytes a server sends the pixels as they are: no length, no zlib.
    #[test]
    fn tight_copy_below_the_threshold_is_uncompressed() {
        let mut s = blank(2, 1);
        // Control byte 0: stream 0, no filter byte, so Copy. Then 2 pixels of 3 bytes.
        let body = [0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff];
        Decoder::new()
            .rect(&mut &tight_rect(2, 1, &body)[..], &mut s)
            .unwrap();
        assert_eq!(s.px, vec![0x00ff_0000, 0x0000_00ff]);
    }

    /// Above it, a compact length and a zlib block off the stream the control byte named.
    #[test]
    fn tight_copy_above_the_threshold_is_deflated() {
        let (w, h) = (4, 2);
        let px: Vec<u8> = (0..w * h * 3).map(|i| (i * 7) as u8).collect();
        let mut z = flate2::Compress::new(flate2::Compression::default(), true);
        let block = deflate(&mut z, &px);

        let mut body = vec![0x00]; // stream 0, Copy
        body.extend_from_slice(&compact(block.len()));
        body.extend_from_slice(&block);

        let mut s = blank(w, h);
        Decoder::new()
            .rect(&mut &tight_rect(w, h, &body)[..], &mut s)
            .unwrap();
        for i in 0..w * h {
            let e = (px[i * 3] as u32) << 16 | (px[i * 3 + 1] as u32) << 8 | px[i * 3 + 2] as u32;
            assert_eq!(s.px[i], e, "pixel {i}");
        }
    }

    /// Two colours are one bit per pixel, most significant first, and every row starts
    /// on a fresh byte. A row that is not a multiple of eight wide is where that goes
    /// wrong, so this one is nine across.
    #[test]
    fn tight_two_colour_palette_is_bit_packed_per_row() {
        let (w, h) = (9, 2);
        // Row 0: 101010101, row 1: 010101010 - each padded out to two bytes. Four
        // bytes in total, which is under the threshold, so they go as they are.
        let data = [0b1010_1010, 0b1000_0000, 0b0101_0101, 0b0000_0000];

        // 0x40: basic compression, stream 0, and a filter byte follows.
        let mut body = vec![0x40, 0x01, 0x01]; // filter Palette, two colours
        body.extend_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60]); // two TPIXELs
        body.extend_from_slice(&data);

        let mut s = blank(w, h);
        Decoder::new()
            .rect(&mut &tight_rect(w, h, &body)[..], &mut s)
            .unwrap();
        let (a, b) = (0x0010_2030, 0x0040_5060);
        assert_eq!(&s.px[..w], &[b, a, b, a, b, a, b, a, b], "row 0");
        assert_eq!(&s.px[w..], &[a, b, a, b, a, b, a, b, a], "row 1");
    }

    /// More than two colours is a whole byte of index per pixel.
    #[test]
    fn tight_palette_indexes_one_byte_per_pixel() {
        let (w, h) = (4, 3);
        let data: Vec<u8> = (0..w * h).map(|i| (i % 3) as u8).collect();
        let mut z = flate2::Compress::new(flate2::Compression::default(), true);
        let block = deflate(&mut z, &data);

        let mut body = vec![0x40, 0x01, 0x02]; // filter Palette, three colours
        body.extend_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0, 3]);
        body.extend_from_slice(&compact(block.len()));
        body.extend_from_slice(&block);

        let mut s = blank(w, h);
        Decoder::new()
            .rect(&mut &tight_rect(w, h, &body)[..], &mut s)
            .unwrap();
        let pal = [0x0001_0000, 0x0000_0200, 0x0000_0003];
        for i in 0..w * h {
            assert_eq!(s.px[i], pal[i % 3], "pixel {i}");
        }
    }

    /// An out-of-range palette index is a corrupt stream, not something to index with.
    #[test]
    fn tight_palette_index_past_the_end_is_refused() {
        let (w, h) = (4, 3);
        let data = vec![9u8; w * h];
        let mut z = flate2::Compress::new(flate2::Compression::default(), true);
        let block = deflate(&mut z, &data);
        let mut body = vec![0x40, 0x01, 0x02];
        body.extend_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0, 3]);
        body.extend_from_slice(&compact(block.len()));
        body.extend_from_slice(&block);

        let mut s = blank(w, h);
        assert!(Decoder::new()
            .rect(&mut &tight_rect(w, h, &body)[..], &mut s)
            .is_err());
    }

    /// The gradient filter sends the difference from a prediction made out of the
    /// pixels left, above and above-left. All-zero differences mean every pixel is
    /// exactly its own prediction, which for the first row and column is black.
    #[test]
    fn tight_gradient_predicts_from_its_neighbours() {
        let (w, h) = (4, 3);
        let mut want = vec![0u32; w * h];
        let mut diff = vec![0u8; w * h * 3];
        // Work out what a server would send for a known picture, then check the
        // decoder puts that picture back.
        let picture: Vec<[u8; 3]> = (0..w * h)
            .map(|i| [(i * 17) as u8, (i * 5) as u8, (255 - i * 9) as u8])
            .collect();
        for row in 0..h {
            for col in 0..w {
                for c in 0..3 {
                    let left = if col > 0 {
                        picture[row * w + col - 1][c] as i32
                    } else {
                        0
                    };
                    let up = if row > 0 {
                        picture[(row - 1) * w + col][c] as i32
                    } else {
                        0
                    };
                    let upleft = if col > 0 && row > 0 {
                        picture[(row - 1) * w + col - 1][c] as i32
                    } else {
                        0
                    };
                    let guess = (left + up - upleft).clamp(0, 255);
                    diff[(row * w + col) * 3 + c] =
                        (picture[row * w + col][c] as i32 - guess) as u8;
                }
                let p = picture[row * w + col];
                want[row * w + col] = (p[0] as u32) << 16 | (p[1] as u32) << 8 | p[2] as u32;
            }
        }
        let mut z = flate2::Compress::new(flate2::Compression::default(), true);
        let block = deflate(&mut z, &diff);
        let mut body = vec![0x40, 0x02]; // filter Gradient
        body.extend_from_slice(&compact(block.len()));
        body.extend_from_slice(&block);

        let mut s = blank(w, h);
        Decoder::new()
            .rect(&mut &tight_rect(w, h, &body)[..], &mut s)
            .unwrap();
        assert_eq!(s.px, want);
    }

    /// The four streams are independent and span the connection, and the server
    /// restarts whichever it likes with the low nibble of the control byte. Getting
    /// that wrong decodes the first rectangle and then produces garbage, which is the
    /// same trap ZRLE's single stream already has a note about.
    #[test]
    fn tight_streams_are_separate_and_resettable() {
        let (w, h) = (4, 2);
        let one: Vec<u8> = (0..w * h * 3).map(|i| i as u8).collect();
        let two: Vec<u8> = (0..w * h * 3).map(|i| (200 - i) as u8).collect();
        let mut dec = Decoder::new();

        // Stream 1 carries two blocks in a row: the second only decodes if the first
        // left the dictionary in place.
        let mut z1 = flate2::Compress::new(flate2::Compression::default(), true);
        for want in [&one, &two] {
            let block = deflate(&mut z1, want);
            let mut body = vec![0x01 << 4]; // stream 1, Copy, no reset
            body.extend_from_slice(&compact(block.len()));
            body.extend_from_slice(&block);
            let mut s = blank(w, h);
            dec.rect(&mut &tight_rect(w, h, &body)[..], &mut s).unwrap();
            assert_eq!(
                s.px[0],
                (want[0] as u32) << 16 | (want[1] as u32) << 8 | want[2] as u32
            );
        }

        // Now restart stream 1 and send a fresh one down it.
        let mut z1b = flate2::Compress::new(flate2::Compression::default(), true);
        let block = deflate(&mut z1b, &one);
        let mut body = vec![0x01 << 4 | 0x02]; // stream 1, and reset stream 1
        body.extend_from_slice(&compact(block.len()));
        body.extend_from_slice(&block);
        let mut s = blank(w, h);
        dec.rect(&mut &tight_rect(w, h, &body)[..], &mut s).unwrap();
        assert_eq!(
            s.px[0],
            (one[0] as u32) << 16 | (one[1] as u32) << 8 | one[2] as u32
        );
    }

    #[test]
    fn compact_lengths_take_one_to_three_bytes() {
        assert_eq!(compact_len(&mut &[0x7f][..]).unwrap(), 127);
        assert_eq!(compact_len(&mut &compact(127)[..]).unwrap(), 127);
        assert_eq!(compact_len(&mut &compact(128)[..]).unwrap(), 128);
        assert_eq!(compact_len(&mut &compact(16383)[..]).unwrap(), 16383);
        assert_eq!(compact_len(&mut &compact(16384)[..]).unwrap(), 16384);
        assert_eq!(compact_len(&mut &compact(1 << 20)[..]).unwrap(), 1 << 20);
        // And the byte counts themselves, since the encoder above is ours too.
        assert_eq!(compact(127).len(), 1);
        assert_eq!(compact(128).len(), 2);
        assert_eq!(compact(16384).len(), 3);
    }

    /// A real JPEG from a real encoder, in four quadrants. Lossy, so the check is
    /// approximate - but a red and blue the wrong way round is not approximate.
    #[test]
    fn tight_jpeg_decodes_with_the_channels_the_right_way_round() {
        let jpeg = include_bytes!("../../tests/fixtures/quadrants.jpg");
        let mut body = vec![0x09 << 4];
        body.extend_from_slice(&compact(jpeg.len()));
        body.extend_from_slice(jpeg);

        let mut s = blank(16, 16);
        Decoder::new()
            .rect(&mut &tight_rect(16, 16, &body)[..], &mut s)
            .unwrap();

        let at = |x: usize, y: usize| {
            let p = s.px[y * 16 + x];
            ((p >> 16) as i32, (p >> 8 & 0xff) as i32, (p & 0xff) as i32)
        };
        let near = |got: (i32, i32, i32), want: (i32, i32, i32), what: &str| {
            let d = (got.0 - want.0).abs() + (got.1 - want.1).abs() + (got.2 - want.2).abs();
            assert!(d < 60, "{what}: got {got:?}, wanted about {want:?}");
        };
        near(at(3, 3), (220, 20, 20), "top left is red");
        near(at(12, 3), (20, 200, 20), "top right is green");
        near(at(3, 12), (20, 20, 220), "bottom left is blue");
        near(at(12, 12), (240, 240, 240), "bottom right is white");
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

    /// Typing the clipboard is the only way to get text onto a Mac, so the conversion
    /// has to be right for the characters people actually paste.
    #[test]
    fn clipboard_text_becomes_typeable_keys() {
        assert_eq!(typed_keys("ab"), [(0x61, false), (0x62, false)]);
        // Uppercase says shift explicitly; a server that maps 'A' to the A key
        // without it types a lowercase 'a'.
        assert_eq!(typed_keys("Hi"), [(0x48, true), (0x69, false)]);
        // A Windows CRLF is one Return, not a stray carriage return as well.
        assert_eq!(
            typed_keys("a\r\nb"),
            [(0x61, false), (0xff0d, false), (0x62, false)]
        );
        assert_eq!(typed_keys("\t"), [(0xff09, false)]);
        // Punctuation goes as its own keysym and is left to the server to place.
        assert_eq!(typed_keys("!"), [(0x21, false)]);
        assert_eq!(
            typed_keys("\u{e9}"),
            [(0xe9, false)],
            "latin-1 is its own keysym"
        );
        // Beyond Latin-1, RFB adds 0x01000000 to the code point.
        assert_eq!(typed_keys("\u{4e2d}"), [(0x0100_4e2d, false)]);
        assert!(typed_keys("").is_empty());
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
