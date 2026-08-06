//! Shared RFB protocol pieces, used by both the client and the server.
//!
//! Only genuinely two-sided things live here. Decoding a rectangle belongs to the
//! client and encoding one belongs to the server, so those stay in their binaries;
//! what they share is the wire primitives, the framebuffer layout, the VNC-auth key
//! derivation (one side answers the challenge, the other sets it) and the clipboard
//! text encoding.

#[cfg(windows)]
pub mod gui;

use std::env;
use std::io::Read;

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

pub fn rd<const N: usize>(s: &mut impl Read) -> Res<[u8; N]> {
    let mut b = [0u8; N];
    s.read_exact(&mut b)?;
    Ok(b)
}
pub fn u8r(s: &mut impl Read) -> Res<u8> {
    Ok(rd::<1>(s)?[0])
}
pub fn u16r(s: &mut impl Read) -> Res<u16> {
    Ok(u16::from_be_bytes(rd::<2>(s)?))
}
pub fn u32r(s: &mut impl Read) -> Res<u32> {
    Ok(u32::from_be_bytes(rd::<4>(s)?))
}
pub fn i32r(s: &mut impl Read) -> Res<i32> {
    Ok(i32::from_be_bytes(rd::<4>(s)?))
}
pub fn blob(s: &mut impl Read, n: usize) -> Res<Vec<u8>> {
    let mut v = vec![0u8; n];
    s.read_exact(&mut v)?;
    Ok(v)
}
/// A u32-prefixed string, used by RFB for error reasons and the desktop name.
pub fn text(s: &mut impl Read) -> Res<String> {
    let n = u32r(s)? as usize;
    Ok(String::from_utf8_lossy(&blob(s, n)?).into_owned())
}

/// RFB's VNC-auth DES key: password truncated/zero-padded to 8 bytes, each byte
/// bit-reversed. The bit reversal is the part everyone gets wrong; see tests.
pub fn vnc_key(password: &str) -> [u8; 8] {
    let mut k = [0u8; 8];
    for (i, b) in password.bytes().take(8).enumerate() {
        k[i] = b.reverse_bits();
    }
    k
}

/// DES-encrypt a VNC-auth challenge in place, 16 bytes as two ECB blocks. The client
/// runs this to answer; the server runs the identical operation to check the answer.
pub fn vnc_des(challenge: &mut [u8; 16], password: &str) {
    use des::cipher::generic_array::GenericArray;
    use des::cipher::{BlockEncrypt, KeyInit};
    let cipher = des::Des::new(&vnc_key(password).into());
    for chunk in challenge.chunks_mut(8) {
        let mut b = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut b);
        chunk.copy_from_slice(&b);
    }
}

/// `VNC_DEBUG=1` prints what was negotiated. Worth having permanently: when a
/// connection is refused, the useful facts are the peer's version, the security types
/// offered and which one was picked, and none of those are visible from the error.
pub fn debug() -> bool {
    env::var("VNC_DEBUG").is_ok()
}

pub struct Screen {
    pub w: usize,
    pub h: usize,
    /// 0x00RRGGBB per pixel - what minifb blits directly, and what a Windows 32bpp
    /// BI_RGB DIB already contains, so neither end needs a translation layer.
    pub px: Vec<u32>,
}

impl Screen {
    pub fn new(w: usize, h: usize) -> Screen {
        Screen {
            w,
            h,
            px: vec![0; w * h],
        }
    }
}

/// The 16-byte PIXEL_FORMAT both ends agree on: 32bpp little-endian true colour with
/// shifts 16/8/0, so a pixel reads back as 0x00RRGGBB and its bytes are B, G, R, pad.
#[rustfmt::skip]
pub const PIXEL_FORMAT: [u8; 16] = [
    32, 24, 0, 1,             // bits-per-pixel, depth, big-endian=no, true-colour=yes
    0, 255, 0, 255, 0, 255,   // red/green/blue max (u16 each)
    16, 8, 0,                 // red/green/blue shift
    0, 0, 0,                  // padding
];

/// ClientCutText (msg 6). RFB clipboard text is ISO 8859-1 with LF line endings, so
/// characters outside Latin-1 become '?' and the CR of a Windows CRLF is dropped.
/// ServerCutText (msg 3) has the same body, so the server reuses this and patches
/// the type byte.
pub fn cut_text_msg(text: &str) -> Vec<u8> {
    let body: Vec<u8> = text
        .chars()
        .filter(|c| *c != '\r')
        .map(|c| if (c as u32) < 256 { c as u8 } else { b'?' })
        .collect();
    let mut m = vec![6, 0, 0, 0];
    m.extend_from_slice(&(body.len() as u32).to_be_bytes());
    m.extend_from_slice(&body);
    m
}

/// The reverse: Latin-1 to a Rust string, putting the CR back so Windows apps see
/// proper line breaks when pasting.
pub fn from_latin1(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| b as char)
        .collect::<String>()
        .replace('\n', "\r\n")
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

    /// The server checks an answer by running the same DES over the challenge it
    /// sent, so this has to be deterministic and match itself exactly.
    #[test]
    fn vnc_des_is_deterministic_and_password_dependent() {
        let challenge = [7u8; 16];
        let (mut a, mut b, mut c) = (challenge, challenge, challenge);
        vnc_des(&mut a, "secret12");
        vnc_des(&mut b, "secret12");
        vnc_des(&mut c, "different");
        assert_eq!(a, b, "same password must give the same answer");
        assert_ne!(a, c, "a different password must not");
        assert_ne!(a, challenge, "and it must actually encrypt");
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
}
