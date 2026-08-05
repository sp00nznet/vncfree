//! vncfree - a free VNC (RFB) client for Windows.
//! Milestone 0: connect, authenticate, pull one full frame, write it to a PPM.
//! No window yet - proving the protocol before adding pixels-on-screen.

use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::TcpStream;

use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

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
    /// 0x00RRGGBB per pixel - the layout minifb wants when we add a window.
    px: Vec<u32>,
}

fn main() -> Res<()> {
    let args: Vec<String> = env::args().collect();
    let Some(addr) = args.get(1) else {
        eprintln!("usage: vncfree <host:port> [out.ppm]");
        eprintln!("password is read from the VNC_PASSWORD env var");
        std::process::exit(2);
    };
    let out = args.get(2).map(String::as_str).unwrap_or("frame.ppm");
    let password = env::var("VNC_PASSWORD").unwrap_or_default();

    let screen = grab(addr, &password)?;
    write_ppm(out, &screen)?;
    println!("wrote {} ({}x{})", out, screen.w, screen.h);
    Ok(())
}

fn grab(addr: &str, password: &str) -> Res<Screen> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_nodelay(true)?;
    let mut w = tcp.try_clone()?;
    let mut r = BufReader::new(tcp);

    // --- version handshake ---
    let ver = rd::<12>(&mut r)?;
    let ver = String::from_utf8_lossy(&ver).trim_end().to_string();
    // ponytail: RFB 3.8 only. 3.3/3.7 differ in how SecurityResult is sent;
    // add them when a real server actually refuses us.
    if !ver.starts_with("RFB 003.008") {
        return Err(format!("unsupported server version {ver:?}, need RFB 003.008").into());
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
    eprintln!("connected: {name:?} {width}x{height}");

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
    // ponytail: add CopyRect/Tight once the window exists and bandwidth matters.
    w.write_all(&[2, 0, 0, 1])?;
    w.write_all(&0i32.to_be_bytes())?;

    // FramebufferUpdateRequest: full screen, non-incremental.
    let mut req = vec![3, 0];
    req.extend_from_slice(&0u16.to_be_bytes());
    req.extend_from_slice(&0u16.to_be_bytes());
    req.extend_from_slice(&(width as u16).to_be_bytes());
    req.extend_from_slice(&(height as u16).to_be_bytes());
    w.write_all(&req)?;

    let mut screen = Screen { w: width, h: height, px: vec![0; width * height] };

    // Read messages until we've consumed one FramebufferUpdate.
    loop {
        match u8r(&mut r)? {
            0 => {
                let _pad = u8r(&mut r)?;
                let rects = u16r(&mut r)?;
                for _ in 0..rects {
                    read_rect(&mut r, &mut screen)?;
                }
                return Ok(screen);
            }
            2 => {} // Bell, no body
            3 => {
                // ServerCutText: 3 padding, then a u32-prefixed string
                blob(&mut r, 3)?;
                text(&mut r)?;
            }
            other => return Err(format!("unexpected server message type {other}").into()),
        }
    }
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
}
