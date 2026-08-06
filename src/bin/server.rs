//! vncfree-server - a free VNC (RFB) server for Windows.
//!
//! Shares your screen and accepts keyboard and mouse. No installer, no service, no
//! account: run the exe, it serves while it is running, close it and nothing is left
//! behind. A password is mandatory - see the note in `run`.
//!
//! Capture is GDI BitBlt into a DIB, which already holds 0x00RRGGBB pixels, so the
//! framebuffer needs no conversion. Input is injected with SendInput.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flate2::{Compress, Compression, FlushCompress};
use vncfree::{blob, cut_text_msg, debug, from_latin1, rd, u16r, u32r, u8r, vnc_des};
use vncfree::{Res, Screen, PIXEL_FORMAT};

mod win {
    //! The only unsafe in the project: screen capture and input injection.
    use std::mem::{size_of, zeroed};
    use std::ptr::null_mut;
    use windows_sys::Win32::Graphics::Gdi::*;
    use windows_sys::Win32::UI::HiDpi::*;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    /// Without this the desktop is reported and captured at its scaled size on a
    /// high-DPI display, so the image is blurry and the pointer lands in the wrong
    /// place.
    pub fn become_dpi_aware() {
        unsafe {
            SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        }
    }

    pub fn screen_size() -> (usize, usize) {
        unsafe {
            (
                GetSystemMetrics(SM_CXSCREEN) as usize,
                GetSystemMetrics(SM_CYSCREEN) as usize,
            )
        }
    }

    /// A reusable capture surface. Creating the DIB once and re-blitting into it is
    /// far cheaper than building one per frame.
    pub struct Capture {
        w: usize,
        h: usize,
        screen: HDC,
        mem: HDC,
        bitmap: HBITMAP,
        bits: *mut u32,
    }

    impl Capture {
        pub fn new(w: usize, h: usize) -> Option<Capture> {
            unsafe {
                let screen = GetDC(null_mut());
                let mem = CreateCompatibleDC(screen);
                let mut bmi: BITMAPINFO = zeroed();
                bmi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
                bmi.bmiHeader.biWidth = w as i32;
                // Negative height asks for a top-down DIB, so row 0 is the top of the
                // screen and the rows already match RFB's order.
                bmi.bmiHeader.biHeight = -(h as i32);
                bmi.bmiHeader.biPlanes = 1;
                bmi.bmiHeader.biBitCount = 32;
                bmi.bmiHeader.biCompression = BI_RGB;
                let mut bits: *mut core::ffi::c_void = null_mut();
                let bitmap = CreateDIBSection(mem, &bmi, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
                if bitmap.is_null() || bits.is_null() {
                    return None;
                }
                SelectObject(mem, bitmap as HGDIOBJ);
                Some(Capture {
                    w,
                    h,
                    screen,
                    mem,
                    bitmap,
                    bits: bits as *mut u32,
                })
            }
        }

        /// Copy the screen into `dst`. The cursor is drawn in by hand because BitBlt
        /// does not include it, and a remote desktop with no visible pointer is
        /// almost unusable.
        pub fn grab(&self, dst: &mut [u32]) {
            unsafe {
                BitBlt(
                    self.mem,
                    0,
                    0,
                    self.w as i32,
                    self.h as i32,
                    self.screen,
                    0,
                    0,
                    SRCCOPY,
                );
                let mut ci: CURSORINFO = zeroed();
                ci.cbSize = size_of::<CURSORINFO>() as u32;
                if GetCursorInfo(&mut ci) != 0 && ci.flags == CURSOR_SHOWING {
                    let mut ii: ICONINFO = zeroed();
                    if GetIconInfo(ci.hCursor, &mut ii) != 0 {
                        DrawIconEx(
                            self.mem,
                            ci.ptScreenPos.x - ii.xHotspot as i32,
                            ci.ptScreenPos.y - ii.yHotspot as i32,
                            ci.hCursor,
                            0,
                            0,
                            0,
                            null_mut(),
                            DI_NORMAL,
                        );
                        if !ii.hbmColor.is_null() {
                            DeleteObject(ii.hbmColor as HGDIOBJ);
                        }
                        if !ii.hbmMask.is_null() {
                            DeleteObject(ii.hbmMask as HGDIOBJ);
                        }
                    }
                }
                // The DIB's top byte is undefined; mask it so pixels compare equal
                // frame to frame instead of producing phantom changes.
                let src = std::slice::from_raw_parts(self.bits, self.w * self.h);
                for (d, s) in dst.iter_mut().zip(src) {
                    *d = s & 0x00FF_FFFF;
                }
            }
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            unsafe {
                DeleteObject(self.bitmap as HGDIOBJ);
                DeleteDC(self.mem);
                ReleaseDC(null_mut(), self.screen);
            }
        }
    }

    fn send(inputs: &[INPUT]) {
        unsafe {
            SendInput(
                inputs.len() as u32,
                inputs.as_ptr(),
                size_of::<INPUT>() as i32,
            );
        }
    }

    /// X11 keysym to Windows virtual key. Letters and digits map to real VKs so that
    /// Ctrl-C and friends reach applications as shortcuts; anything else printable is
    /// injected as a Unicode character, which sidesteps keyboard-layout differences
    /// entirely. Returns None for keysyms with no virtual key.
    fn vk_for(sym: u32) -> Option<u16> {
        Some(match sym {
            0x61..=0x7a => (sym - 0x61 + 0x41) as u16, // a-z -> VK_A..VK_Z
            0x41..=0x5a => sym as u16,                 // A-Z already are the VK values
            0x30..=0x39 => sym as u16,                 // 0-9
            0x20 => VK_SPACE,
            0xff08 => VK_BACK,
            0xff09 => VK_TAB,
            0xff0d => VK_RETURN,
            0xff1b => VK_ESCAPE,
            0xff50 => VK_HOME,
            0xff51 => VK_LEFT,
            0xff52 => VK_UP,
            0xff53 => VK_RIGHT,
            0xff54 => VK_DOWN,
            0xff55 => VK_PRIOR,
            0xff56 => VK_NEXT,
            0xff57 => VK_END,
            0xff63 => VK_INSERT,
            0xffff => VK_DELETE,
            0xff13 => VK_PAUSE,
            0xff14 => VK_SCROLL,
            0xff7f => VK_NUMLOCK,
            0xffe5 => VK_CAPITAL,
            0xffe1 => VK_LSHIFT,
            0xffe2 => VK_RSHIFT,
            0xffe3 => VK_LCONTROL,
            0xffe4 => VK_RCONTROL,
            0xffe9 => VK_LMENU,
            0xffea => VK_RMENU,
            0xffeb => VK_LWIN,
            0xffec => VK_RWIN,
            0xffbe..=0xffc9 => (sym - 0xffbe) as u16 + VK_F1,
            _ => return None,
        })
    }

    pub fn inject_key(sym: u32, down: bool) {
        let mut i: INPUT = unsafe { zeroed() };
        i.r#type = INPUT_KEYBOARD;
        match vk_for(sym) {
            Some(vk) => {
                i.Anonymous.ki.wVk = vk;
                i.Anonymous.ki.dwFlags = if down { 0 } else { KEYEVENTF_KEYUP };
            }
            // Printable but unmapped: type the character itself.
            None if sym < 0x1_0000 => {
                i.Anonymous.ki.wScan = sym as u16;
                i.Anonymous.ki.dwFlags = KEYEVENTF_UNICODE | if down { 0 } else { KEYEVENTF_KEYUP };
            }
            None => return,
        }
        send(&[i]);
    }

    /// Our framebuffer is in physical pixels, so the pointer must be placed in
    /// physical pixels. SendInput's MOUSEEVENTF_ABSOLUTE is not the way to do that:
    /// its 0..65535 range maps onto the *logical* desktop, so on a 200% display every
    /// coordinate lands at half the intended position. SetPhysicalCursorPos takes
    /// physical pixels directly and still raises the usual mouse-move messages.
    pub fn move_pointer(x: u16, y: u16, _w: usize, _h: usize) {
        unsafe {
            SetPhysicalCursorPos(x as i32, y as i32);
        }
    }

    pub fn buttons(prev: u8, now: u8) {
        // Bits 0-2 are left/middle/right; 3-4 are the wheel, which RFB models as a
        // button being clicked rather than as a scroll message.
        for (bit, down, up) in [
            (0u8, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
            (1, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
            (2, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
        ] {
            let (was, is) = (prev & (1 << bit) != 0, now & (1 << bit) != 0);
            if was != is {
                let mut i: INPUT = unsafe { zeroed() };
                i.r#type = INPUT_MOUSE;
                i.Anonymous.mi.dwFlags = if is { down } else { up };
                send(&[i]);
            }
        }
        for (bit, delta) in [(3u8, 120i32), (4, -120)] {
            if now & (1 << bit) != 0 && prev & (1 << bit) == 0 {
                let mut i: INPUT = unsafe { zeroed() };
                i.r#type = INPUT_MOUSE;
                i.Anonymous.mi.mouseData = delta as u32;
                i.Anonymous.mi.dwFlags = MOUSEEVENTF_WHEEL;
                send(&[i]);
            }
        }
    }
}

/// The pixel format the client asked for. We always hold 0x00RRGGBB internally and
/// compose on the way out, so a client wanting different shifts still works.
#[derive(Clone, Copy, Debug)]
struct PixFmt {
    big_endian: bool,
    rshift: u32,
    gshift: u32,
    bshift: u32,
}

impl Default for PixFmt {
    fn default() -> PixFmt {
        PixFmt {
            big_endian: false,
            rshift: 16,
            gshift: 8,
            bshift: 0,
        }
    }
}

impl PixFmt {
    fn parse(f: &[u8]) -> Res<PixFmt> {
        let (bpp, truecolour) = (f[0], f[3]);
        if bpp != 32 || truecolour == 0 {
            return Err(format!(
                "client asked for {bpp}bpp truecolour={truecolour}; vncfree-server only \
                 serves 32bpp true colour"
            )
            .into());
        }
        Ok(PixFmt {
            big_endian: f[2] != 0,
            rshift: f[10] as u32,
            gshift: f[11] as u32,
            bshift: f[12] as u32,
        })
    }

    fn pixel(&self, p: u32) -> [u8; 4] {
        let v = ((p >> 16) & 255) << self.rshift
            | ((p >> 8) & 255) << self.gshift
            | (p & 255) << self.bshift;
        if self.big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }

    /// A ZRLE "compressed pixel": the same pixel minus its unused byte. This is only
    /// legal when all the colour fits in the low three bytes, which it does for any
    /// shift of 16 or less. A client using an exotic layout gets Raw instead.
    fn cpixel(&self, p: u32) -> Option<[u8; 3]> {
        if self.rshift > 16 || self.gshift > 16 || self.bshift > 16 {
            return None;
        }
        let b = self.pixel(p);
        Some(if self.big_endian {
            [b[1], b[2], b[3]]
        } else {
            [b[0], b[1], b[2]]
        })
    }
}

const TILE: usize = 64;

/// Changed regions between two frames, as 64-pixel tile rows with horizontally
/// adjacent tiles merged into runs. Merging matters: without it a full-screen change
/// at 1080p is 510 separate rectangles, each carrying its own header.
fn changed_rects(
    prev: &[u32],
    cur: &[u32],
    w: usize,
    h: usize,
) -> Vec<(usize, usize, usize, usize)> {
    let mut rects = Vec::new();
    let mut ty = 0;
    while ty < h {
        let th = TILE.min(h - ty);
        let mut tx = 0;
        let mut run: Option<usize> = None;
        while tx < w {
            let tw = TILE.min(w - tx);
            let changed = (0..th).any(|r| {
                let o = (ty + r) * w + tx;
                prev[o..o + tw] != cur[o..o + tw]
            });
            match (changed, run) {
                (true, None) => run = Some(tx),
                (false, Some(s)) => {
                    rects.push((s, ty, tx - s, th));
                    run = None;
                }
                _ => {}
            }
            tx += tw;
        }
        if let Some(s) = run {
            rects.push((s, ty, w - s, th));
        }
        ty += TILE;
    }
    rects
}

/// Encode one 64x64 (or smaller, at the edges) ZRLE tile.
///
/// Three of the five subencodings are produced: solid, packed palette and raw. The
/// two RLE forms are a further squeeze on top and are deliberately skipped - our
/// client decodes all five, so this only ever costs bytes, never compatibility.
fn encode_tile(out: &mut Vec<u8>, s: &Screen, x: usize, y: usize, w: usize, h: usize, f: &PixFmt) {
    let at = |row: usize, col: usize| s.px[(y + row) * s.w + x + col];

    // Distinct colours, giving up once a palette would be too large to be worth it.
    let mut palette: Vec<u32> = Vec::new();
    'scan: for row in 0..h {
        for col in 0..w {
            let p = at(row, col);
            if !palette.contains(&p) {
                if palette.len() == 16 {
                    palette.clear();
                    break 'scan;
                }
                palette.push(p);
            }
        }
    }

    match palette.len() {
        // Too many colours to index: spell every pixel out.
        0 => {
            out.push(0);
            for row in 0..h {
                for col in 0..w {
                    out.extend_from_slice(&f.cpixel(at(row, col)).unwrap_or([0; 3]));
                }
            }
        }
        // One colour for the whole tile, which is most of a typical desktop.
        1 => {
            out.push(1);
            out.extend_from_slice(&f.cpixel(palette[0]).unwrap_or([0; 3]));
        }
        n => {
            out.push(n as u8);
            for c in &palette {
                out.extend_from_slice(&f.cpixel(*c).unwrap_or([0; 3]));
            }
            let bits = match n {
                2 => 1,
                3..=4 => 2,
                _ => 4,
            };
            // Indices are packed most-significant-bit first and every row restarts on
            // a byte boundary.
            for row in 0..h {
                let (mut byte, mut used) = (0u8, 0);
                for col in 0..w {
                    let idx = palette.iter().position(|&c| c == at(row, col)).unwrap() as u8;
                    byte |= idx << (8 - bits - used);
                    used += bits;
                    if used == 8 {
                        out.push(byte);
                        byte = 0;
                        used = 0;
                    }
                }
                if used > 0 {
                    out.push(byte);
                }
            }
        }
    }
}

/// Push bytes through the connection-wide deflate stream and flush so the client can
/// decode this rectangle immediately.
fn deflate(z: &mut Compress, input: &[u8]) -> Res<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 2 + 1024);
    let mut consumed = 0;
    while consumed < input.len() {
        if out.len() == out.capacity() {
            out.reserve(4096);
        }
        let in0 = z.total_in();
        z.compress_vec(&input[consumed..], &mut out, FlushCompress::None)?;
        consumed += (z.total_in() - in0) as usize;
        if z.total_in() == in0 && out.len() < out.capacity() {
            return Err("deflate stalled".into());
        }
    }
    // Exactly one sync flush. Calling Sync repeatedly emits a fresh marker every time
    // and never reports being finished, which is an easy infinite loop to write.
    loop {
        if out.len() == out.capacity() {
            out.reserve(4096);
        }
        let before = out.len();
        z.compress_vec(&[], &mut out, FlushCompress::Sync)?;
        if out.len() < out.capacity() || out.len() == before {
            return Ok(out);
        }
    }
}

fn zrle_update(
    z: &mut Compress,
    s: &Screen,
    rects: &[(usize, usize, usize, usize)],
    fmt: &PixFmt,
) -> Res<Vec<u8>> {
    let mut out = vec![0u8, 0];
    out.extend_from_slice(&(rects.len() as u16).to_be_bytes());
    for &(x, y, w, h) in rects {
        let mut tiles = Vec::new();
        for ty in (0..h).step_by(64) {
            for tx in (0..w).step_by(64) {
                let (tw, th) = ((w - tx).min(64), (h - ty).min(64));
                encode_tile(&mut tiles, s, x + tx, y + ty, tw, th, fmt);
            }
        }
        let body = deflate(z, &tiles)?;
        out.extend_from_slice(&(x as u16).to_be_bytes());
        out.extend_from_slice(&(y as u16).to_be_bytes());
        out.extend_from_slice(&(w as u16).to_be_bytes());
        out.extend_from_slice(&(h as u16).to_be_bytes());
        out.extend_from_slice(&16i32.to_be_bytes()); // ZRLE
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
    }
    Ok(out)
}

fn raw_update(s: &Screen, rects: &[(usize, usize, usize, usize)], fmt: &PixFmt) -> Vec<u8> {
    let mut out = vec![0u8, 0]; // FramebufferUpdate, padding
    out.extend_from_slice(&(rects.len() as u16).to_be_bytes());
    for &(x, y, w, h) in rects {
        out.extend_from_slice(&(x as u16).to_be_bytes());
        out.extend_from_slice(&(y as u16).to_be_bytes());
        out.extend_from_slice(&(w as u16).to_be_bytes());
        out.extend_from_slice(&(h as u16).to_be_bytes());
        out.extend_from_slice(&0i32.to_be_bytes()); // Raw
        for row in y..y + h {
            for col in x..x + w {
                out.extend_from_slice(&fmt.pixel(s.px[row * s.w + col]));
            }
        }
    }
    out
}

/// Shared between a client's reader thread and its sender thread.
struct Shared {
    out: Mutex<TcpStream>,
    fmt: Mutex<PixFmt>,
    /// The client has an outstanding FramebufferUpdateRequest. RFB is request-driven:
    /// nothing may be sent until one arrives.
    wants: AtomicBool,
    /// The client's copy of the screen is valid, so only changes need to go out.
    incremental: AtomicBool,
    /// The client listed ZRLE in SetEncodings. Sending an encoding a client never
    /// asked for is a protocol violation, so Raw is the default until it does.
    zrle: AtomicBool,
    alive: AtomicBool,
    clip: Mutex<String>,
}

/// Set once the password dialog has been used, which means the program was almost
/// certainly launched by double-clicking and has no console to print to.
static FROM_GUI: AtomicBool = AtomicBool::new(false);

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        if FROM_GUI.load(Ordering::Relaxed) {
            vncfree::gui::alert("vncfree-server", &e.to_string());
        }
        std::process::exit(1);
    }
}

/// Ask for a password before serving anything. Shows this machine's address on the
/// local network so the person at the other end knows what to type.
///
/// No public IP is shown. Finding one means asking a third-party server, which sits
/// badly with a program that promises no telemetry, and putting a DES-authenticated
/// VNC server on the open internet is not something to encourage with a helpful
/// label. Tunnel it instead.
fn ask_for_password(bind: &str) -> Res<Option<(String, String)>> {
    let note = match vncfree::gui::lan_ip() {
        Some(ip) => format!(
            "This machine is {ip} on the local network.\n\
             Do not port-forward this. Tunnel over SSH or a VPN."
        ),
        None => "Could not work out this machine's local address.".to_string(),
    };
    let mut fields = vec![
        vncfree::gui::Field::new("Password", true, true),
        vncfree::gui::Field::new("Listen on", false, true),
    ];
    fields[1].value = bind.to_string();
    let check: vncfree::gui::Validator =
        |f| vncfree::gui::check_host_port("Listen on", &f[1].value);
    if !vncfree::gui::form(
        "vncfree-server",
        &note,
        &mut fields,
        "Start server",
        Some(check),
    ) {
        return Ok(None);
    }
    Ok(Some((
        fields[0].value.clone(),
        fields[1].value.trim().to_string(),
    )))
}

fn run() -> Res<()> {
    win::become_dpi_aware();

    // A password is mandatory. An unauthenticated VNC server on a listening port
    // hands the whole desktop to anyone who can reach it, and defaulting to open is
    // exactly the decision that makes remote-access software dangerous.
    let mut password = std::env::var("VNC_PASSWORD").unwrap_or_default();
    let mut bind = std::env::var("VNC_BIND").unwrap_or_else(|_| "0.0.0.0:5900".into());

    // No password in the environment: ask for one. The dialog's Start button stays
    // disabled until a password is typed, so there is no path to an open server.
    if password.is_empty() {
        FROM_GUI.store(true, Ordering::Relaxed);
        match ask_for_password(&bind)? {
            Some((p, b)) => {
                password = p;
                bind = b;
            }
            None => return Ok(()), // window closed
        }
    }
    if password.is_empty() {
        return Err("set VNC_PASSWORD to a password of up to 8 characters.\n\
                    vncfree-server will not run without one - an open VNC port gives \
                    anyone who can reach it full control of this desktop.\n\
                    Note that VNC auth is DES and weak: tunnel over SSH or a VPN if \
                    the network is not trusted."
            .into());
    }
    if password.len() > 8 {
        eprintln!("warning: VNC auth uses only the first 8 characters of the password");
    }

    let listener =
        TcpListener::bind(&bind).map_err(|e| format!("could not listen on {bind}: {e}"))?;
    let (w, h) = win::screen_size();
    println!("vncfree-server listening on {bind}, sharing {w}x{h}");

    for stream in listener.incoming() {
        let stream = stream?;
        let password = password.clone();
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        std::thread::spawn(move || {
            println!("client connected: {peer}");
            match serve(stream, &password, w, h) {
                Ok(()) => println!("client {peer} disconnected"),
                Err(e) => println!("client {peer} finished: {e}"),
            }
        });
    }
    Ok(())
}

fn serve(mut tcp: TcpStream, password: &str, w: usize, h: usize) -> Res<()> {
    tcp.set_nodelay(true)?;

    // --- version ---
    tcp.write_all(b"RFB 003.008\n")?;
    let ver = String::from_utf8_lossy(&rd::<12>(&mut tcp)?)
        .trim_end()
        .to_string();
    if debug() {
        eprintln!("[debug] client speaks {ver:?}");
    }

    // --- security: VNC auth only, because a password is always required ---
    tcp.write_all(&[1, 2])?; // one type on offer: 2 = VNC auth
    if u8r(&mut tcp)? != 2 {
        return refuse(&mut tcp, b"vncfree-server only offers VNC authentication");
    }

    let mut challenge = [0u8; 16];
    getrandom::fill(&mut challenge)?;
    tcp.write_all(&challenge)?;
    let answer = rd::<16>(&mut tcp)?;
    let mut expected = challenge;
    vnc_des(&mut expected, password);
    if answer != expected {
        return refuse(&mut tcp, b"authentication failed");
    }
    tcp.write_all(&0u32.to_be_bytes())?; // SecurityResult: OK

    // --- init ---
    let _shared_flag = u8r(&mut tcp)?;
    let name = format!("{} (vncfree)", hostname());
    let mut init = Vec::new();
    init.extend_from_slice(&(w as u16).to_be_bytes());
    init.extend_from_slice(&(h as u16).to_be_bytes());
    init.extend_from_slice(&PIXEL_FORMAT);
    init.extend_from_slice(&(name.len() as u32).to_be_bytes());
    init.extend_from_slice(name.as_bytes());
    tcp.write_all(&init)?;

    let shared = Arc::new(Shared {
        out: Mutex::new(tcp.try_clone()?),
        fmt: Mutex::new(PixFmt::default()),
        wants: AtomicBool::new(false),
        incremental: AtomicBool::new(false),
        zrle: AtomicBool::new(false),
        alive: AtomicBool::new(true),
        clip: Mutex::new(String::new()),
    });

    let sender = shared.clone();
    std::thread::spawn(move || {
        if let Err(e) = send_frames(&sender, w, h) {
            if sender.alive.load(Ordering::Relaxed) {
                eprintln!("sender stopped: {e}");
            }
        }
        sender.alive.store(false, Ordering::Relaxed);
    });

    let result = read_client(&mut tcp, &shared, w, h);
    shared.alive.store(false, Ordering::Relaxed);
    result
}

fn refuse(tcp: &mut TcpStream, reason: &[u8]) -> Res<()> {
    tcp.write_all(&1u32.to_be_bytes())?;
    tcp.write_all(&(reason.len() as u32).to_be_bytes())?;
    tcp.write_all(reason)?;
    Err(String::from_utf8_lossy(reason).into_owned().into())
}

fn read_client(tcp: &mut TcpStream, shared: &Arc<Shared>, w: usize, h: usize) -> Res<()> {
    let mut mask = 0u8;
    let mut board = arboard::Clipboard::new().ok();
    while shared.alive.load(Ordering::Relaxed) {
        match u8r(tcp)? {
            0 => {
                // SetPixelFormat: 3 padding then the 16-byte format.
                blob(tcp, 3)?;
                let f = blob(tcp, 16)?;
                *shared.fmt.lock().unwrap() = PixFmt::parse(&f)?;
                // The client's copy of the screen is now in the wrong format, so the
                // next update has to be a full one.
                shared.incremental.store(false, Ordering::Relaxed);
            }
            2 => {
                blob(tcp, 1)?;
                let n = u16r(tcp)? as usize;
                let list = blob(tcp, n * 4)?;
                let encs: Vec<i32> = list
                    .chunks(4)
                    .map(|c| i32::from_be_bytes(c.try_into().unwrap()))
                    .collect();
                shared.zrle.store(encs.contains(&16), Ordering::Relaxed);
                if debug() {
                    eprintln!(
                        "[debug] client supports encodings {encs:?}, using {}",
                        if encs.contains(&16) { "ZRLE" } else { "Raw" }
                    );
                }
            }
            3 => {
                let incremental = u8r(tcp)? != 0;
                blob(tcp, 8)?; // x, y, w, h - we always answer for the whole screen
                if !incremental {
                    shared.incremental.store(false, Ordering::Relaxed);
                }
                shared.wants.store(true, Ordering::Relaxed);
            }
            4 => {
                let down = u8r(tcp)? != 0;
                blob(tcp, 2)?;
                win::inject_key(u32r(tcp)?, down);
            }
            5 => {
                let now = u8r(tcp)?;
                let (x, y) = (u16r(tcp)?, u16r(tcp)?);
                win::move_pointer(x, y, w, h);
                win::buttons(mask, now);
                mask = now;
            }
            6 => {
                blob(tcp, 3)?;
                let n = u32r(tcp)? as usize;
                let body = blob(tcp, n)?;
                let text = from_latin1(&body);
                *shared.clip.lock().unwrap() = text.clone();
                if let Some(b) = board.as_mut() {
                    let _ = b.set_text(text);
                }
            }
            other => return Err(format!("unknown client message type {other}").into()),
        }
    }
    Ok(())
}

fn send_frames(shared: &Arc<Shared>, w: usize, h: usize) -> Res<()> {
    let mut cur = Screen::new(w, h);
    let mut prev = Screen::new(w, h);
    let mut first = true;
    let cap = win::Capture::new(w, h).ok_or("could not create the capture surface")?;
    // One deflate stream for the whole connection. ZRLE's zlib state spans the
    // session, not a rectangle; restarting it per rectangle decodes the first one and
    // then produces garbage on the client forever.
    let mut deflater = Compress::new(Compression::default(), true);

    let mut board = arboard::Clipboard::new().ok();
    if let Some(b) = board.as_mut() {
        if let Ok(t) = b.get_text() {
            *shared.clip.lock().unwrap() = t;
        }
    }
    let mut clip_tick = 0u32;

    while shared.alive.load(Ordering::Relaxed) {
        // Our clipboard changing is worth telling the client about whether or not it
        // has an update outstanding.
        if clip_tick == 0 {
            clip_tick = 50;
            if let Some(b) = board.as_mut() {
                if let Ok(t) = b.get_text() {
                    let mut last = shared.clip.lock().unwrap();
                    if !t.is_empty() && *last != t {
                        *last = t.clone();
                        drop(last);
                        let mut m = cut_text_msg(&t);
                        m[0] = 3; // ServerCutText carries the same body
                        shared.out.lock().unwrap().write_all(&m)?;
                    }
                }
            }
        }
        clip_tick -= 1;

        if !shared.wants.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }

        cap.grab(&mut cur.px);
        let full = first || !shared.incremental.load(Ordering::Relaxed);
        let rects = if full {
            vec![(0, 0, w, h)]
        } else {
            changed_rects(&prev.px, &cur.px, w, h)
        };

        if rects.is_empty() {
            // An incremental request stays outstanding until something actually
            // changes; answering with zero rectangles would spin the client.
            std::thread::sleep(Duration::from_millis(20));
            continue;
        }

        let fmt = *shared.fmt.lock().unwrap();
        // ZRLE needs both the client's blessing and a pixel layout that has a legal
        // 3-byte CPIXEL; otherwise fall back to Raw, which every client understands.
        let msg = if shared.zrle.load(Ordering::Relaxed) && fmt.cpixel(0).is_some() {
            zrle_update(&mut deflater, &cur, &rects, &fmt)?
        } else {
            raw_update(&cur, &rects, &fmt)
        };
        if debug() {
            let pixels: usize = rects.iter().map(|r| r.2 * r.3).sum();
            eprintln!(
                "[debug] update: {} rect(s), {pixels} px, {} bytes on the wire ({:.1}% of raw)",
                rects.len(),
                msg.len(),
                100.0 * msg.len() as f64 / (pixels * 4).max(1) as f64
            );
        }
        shared.out.lock().unwrap().write_all(&msg)?;

        prev.px.copy_from_slice(&cur.px);
        first = false;
        shared.incremental.store(true, Ordering::Relaxed);
        shared.wants.store(false, Ordering::Relaxed);
    }
    Ok(())
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_frames_produce_no_rectangles() {
        let a = vec![0u32; 128 * 128];
        assert!(changed_rects(&a, &a, 128, 128).is_empty());
    }

    #[test]
    fn a_single_changed_pixel_yields_only_its_tile() {
        let a = vec![0u32; 128 * 128];
        let mut b = a.clone();
        b[70 * 128 + 70] = 1; // inside tile (1,1)
        assert_eq!(changed_rects(&a, &b, 128, 128), vec![(64, 64, 64, 64)]);
    }

    /// Adjacent changed tiles must merge, otherwise a full-screen change at 1080p is
    /// 510 rectangles each carrying its own 12-byte header.
    #[test]
    fn adjacent_tiles_merge_into_one_rectangle() {
        let a = vec![0u32; 192 * 64];
        let mut b = a.clone();
        b[..192].fill(1); // whole top row changed, spanning three tiles
        assert_eq!(changed_rects(&a, &b, 192, 64), vec![(0, 0, 192, 64)]);
    }

    /// A gap must split the run rather than swallowing the unchanged middle tile.
    #[test]
    fn a_gap_splits_the_run() {
        let a = vec![0u32; 192 * 64];
        let mut b = a.clone();
        b[0] = 1;
        b[130] = 1; // tiles 0 and 2 changed, tile 1 untouched
        assert_eq!(
            changed_rects(&a, &b, 192, 64),
            vec![(0, 0, 64, 64), (128, 0, 64, 64)]
        );
    }

    /// Edge tiles are partial when the screen is not a multiple of 64.
    #[test]
    fn edge_tiles_are_clipped_to_the_screen() {
        let (w, h) = (100usize, 70usize);
        let a = vec![0u32; w * h];
        let mut b = a.clone();
        b[69 * w + 99] = 1; // bottom-right corner
        assert_eq!(changed_rects(&a, &b, w, h), vec![(64, 64, 36, 6)]);
    }

    #[test]
    fn pixels_are_composed_using_the_clients_shifts() {
        let bgr = PixFmt::default(); // shifts 16/8/0, little-endian
        assert_eq!(bgr.pixel(0x00AA_BBCC), [0xCC, 0xBB, 0xAA, 0]);

        let swapped = PixFmt {
            big_endian: false,
            rshift: 0,
            gshift: 8,
            bshift: 16,
        };
        assert_eq!(swapped.pixel(0x00AA_BBCC), [0xAA, 0xBB, 0xCC, 0]);

        let be = PixFmt {
            big_endian: true,
            ..PixFmt::default()
        };
        assert_eq!(be.pixel(0x00AA_BBCC), [0, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn a_non_32bpp_client_is_refused_with_a_clear_message() {
        let mut f = PIXEL_FORMAT;
        f[0] = 16; // bits-per-pixel
        let e = PixFmt::parse(&f).unwrap_err().to_string();
        assert!(e.contains("32bpp"), "{e}");
        assert!(PixFmt::parse(&PIXEL_FORMAT).is_ok());
    }

    fn tile_of(px: &[u32], w: usize, h: usize) -> Vec<u8> {
        let s = Screen {
            w,
            h,
            px: px.to_vec(),
        };
        let mut out = Vec::new();
        encode_tile(&mut out, &s, 0, 0, w, h, &PixFmt::default());
        out
    }

    #[test]
    fn a_uniform_tile_becomes_one_solid_pixel() {
        let out = tile_of(&[0x00AA_BBCC; 16], 4, 4);
        // Subencoding 1, then a single CPIXEL as B, G, R.
        assert_eq!(out, vec![1, 0xCC, 0xBB, 0xAA]);
    }

    #[test]
    fn two_colours_pack_one_bit_per_pixel_msb_first() {
        // Row 0 is A,B,A,B and row 1 is B,B,A,A.
        let (a, b) = (0x0000_0001, 0x0000_0002);
        let out = tile_of(&[a, b, a, b, b, b, a, a], 4, 2);
        assert_eq!(out[0], 2, "palette of two");
        assert_eq!(&out[1..4], &[1, 0, 0], "first palette entry is A");
        assert_eq!(&out[4..7], &[2, 0, 0], "second is B");
        // 4 pixels at 1 bit each, MSB first, each row padded to its own byte.
        assert_eq!(out[7], 0b0101_0000, "row 0: A B A B");
        assert_eq!(out[8], 0b1100_0000, "row 1: B B A A");
        assert_eq!(out.len(), 9);
    }

    /// Four colours need two bits per index, still packed from the top of the byte.
    #[test]
    fn four_colours_pack_two_bits_per_pixel() {
        let out = tile_of(&[1, 2, 3, 4], 4, 1);
        assert_eq!(out[0], 4, "palette of four");
        assert_eq!(out.len(), 1 + 4 * 3 + 1, "one packed byte for four pixels");
        assert_eq!(*out.last().unwrap(), 0b00_01_10_11);
    }

    /// More than 16 colours cannot be indexed, so the tile falls back to raw pixels.
    #[test]
    fn more_than_sixteen_colours_falls_back_to_raw() {
        let px: Vec<u32> = (0..20u32).collect();
        let out = tile_of(&px, 20, 1);
        assert_eq!(out[0], 0, "raw subencoding");
        assert_eq!(out.len(), 1 + 20 * 3, "three bytes per pixel, no palette");
    }

    /// CPIXELs drop the unused byte, and an exotic layout has none to drop.
    #[test]
    fn cpixel_drops_the_unused_byte_or_refuses() {
        assert_eq!(
            PixFmt::default().cpixel(0x00AA_BBCC),
            Some([0xCC, 0xBB, 0xAA])
        );
        let be = PixFmt {
            big_endian: true,
            ..PixFmt::default()
        };
        assert_eq!(be.cpixel(0x00AA_BBCC), Some([0xAA, 0xBB, 0xCC]));
        // Colour living in the top three bytes has no 3-byte little-endian form here.
        let high = PixFmt {
            big_endian: false,
            rshift: 24,
            gshift: 16,
            bshift: 8,
        };
        assert_eq!(high.cpixel(0x00AA_BBCC), None);
    }

    /// The deflate stream spans the connection, so a second rectangle must not
    /// restart it - and the helper must terminate, which an over-eager flush loop
    /// famously does not.
    #[test]
    fn deflate_is_streaming_and_terminates() {
        let mut z = Compress::new(Compression::default(), true);
        let first = deflate(&mut z, b"hello hello hello").unwrap();
        let second = deflate(&mut z, b"hello hello hello").unwrap();
        assert!(!first.is_empty());
        assert!(!second.is_empty());
        // The second copy is cheaper because the first is still in the window.
        assert!(
            second.len() < first.len(),
            "{} vs {}",
            second.len(),
            first.len()
        );
    }

    #[test]
    fn zrle_rect_header_is_well_formed() {
        let mut z = Compress::new(Compression::default(), true);
        let s = Screen::new(4, 4);
        let msg = zrle_update(&mut z, &s, &[(0, 0, 4, 4)], &PixFmt::default()).unwrap();
        assert_eq!(msg[0], 0, "FramebufferUpdate");
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 1, "one rectangle");
        assert_eq!(
            i32::from_be_bytes(msg[12..16].try_into().unwrap()),
            16,
            "ZRLE"
        );
        let len = u32::from_be_bytes(msg[16..20].try_into().unwrap()) as usize;
        assert_eq!(msg.len(), 20 + len, "body length must match the header");
    }

    #[test]
    fn raw_update_header_is_well_formed() {
        let s = Screen::new(2, 1);
        let msg = raw_update(&s, &[(0, 0, 2, 1)], &PixFmt::default());
        assert_eq!(msg[0], 0, "FramebufferUpdate");
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 1, "one rectangle");
        assert_eq!(u16::from_be_bytes([msg[8], msg[9]]), 2, "width");
        assert_eq!(
            i32::from_be_bytes(msg[12..16].try_into().unwrap()),
            0,
            "Raw"
        );
        assert_eq!(msg.len(), 4 + 12 + 2 * 4);
    }
}
