//! The client against servers older than 3.8, driven as a real process.
//!
//! These three versions differ in small ways that are invisible until something
//! deadlocks: 3.3 states the security type instead of offering a list and takes no
//! answer, and neither 3.3 nor 3.7 sends a reason with a failed SecurityResult. Getting
//! one of those wrong leaves the client waiting for bytes that are never coming, which
//! looks like a hung network rather than a protocol mistake, so it is worth standing a
//! server up and watching a whole session through.
//!
//! Each test speaks just enough RFB to get one frame to the client, then checks the
//! pixels the client wrote out.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;

const PASSWORD: &str = "hunter22";
const W: usize = 4;
const H: usize = 3;

fn rd<const N: usize>(s: &mut TcpStream) -> [u8; N] {
    let mut b = [0u8; N];
    s.read_exact(&mut b).unwrap();
    b
}

/// One pixel of the test picture, as the client will reconstruct it.
fn colour(i: usize) -> u32 {
    (i as u32 * 0x0011_2233) & 0x00FF_FFFF
}

/// Serve exactly one frame to one client, speaking the given RFB minor version, and
/// return the version string the client answered with.
fn serve_one(listener: TcpListener, minor: u32) -> String {
    let (mut s, _) = listener.accept().unwrap();
    // A client waiting for a message this version never sends would otherwise deadlock
    // against a server waiting for the message it should have sent instead, and the
    // test would hang rather than fail. That is exactly the bug these tests exist to
    // catch, so it has to be the kind of failure a machine reports.
    s.set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();

    // --- version ---
    s.write_all(format!("RFB 003.{minor:03}\n").as_bytes())
        .unwrap();
    let answered = String::from_utf8_lossy(&rd::<12>(&mut s))
        .trim_end()
        .to_string();

    // --- security ---
    if minor == 3 {
        // 3.3 states the type in one word and expects nothing back.
        s.write_all(&2u32.to_be_bytes()).unwrap();
    } else {
        s.write_all(&[1, 2]).unwrap(); // a list of one: VNC auth
        assert_eq!(rd::<1>(&mut s)[0], 2, "client picked VNC auth");
    }

    let challenge = [7u8; 16];
    s.write_all(&challenge).unwrap();
    let answer = rd::<16>(&mut s);
    let mut expected = challenge;
    vncfree::vnc_des(&mut expected, PASSWORD);
    assert_eq!(answer, expected, "the client's response to the challenge");
    s.write_all(&0u32.to_be_bytes()).unwrap(); // SecurityResult: OK

    // --- init ---
    assert_eq!(rd::<1>(&mut s)[0], 1, "ClientInit, shared");
    let name = b"old server";
    let mut init = Vec::new();
    init.extend_from_slice(&(W as u16).to_be_bytes());
    init.extend_from_slice(&(H as u16).to_be_bytes());
    init.extend_from_slice(&vncfree::PIXEL_FORMAT);
    init.extend_from_slice(&(name.len() as u32).to_be_bytes());
    init.extend_from_slice(name);
    s.write_all(&init).unwrap();

    // --- read client messages until it asks for a frame ---
    loop {
        match rd::<1>(&mut s)[0] {
            0 => {
                rd::<3>(&mut s);
                rd::<16>(&mut s);
            }
            2 => {
                rd::<1>(&mut s);
                let n = u16::from_be_bytes(rd::<2>(&mut s)) as usize;
                let mut list = vec![0u8; n * 4];
                s.read_exact(&mut list).unwrap();
            }
            3 => {
                rd::<9>(&mut s); // incremental + x, y, w, h
                break;
            }
            other => panic!("unexpected client message type {other}"),
        }
    }

    // --- one Raw rectangle covering the whole screen ---
    let mut msg = vec![0u8, 0];
    msg.extend_from_slice(&1u16.to_be_bytes()); // one rectangle
    msg.extend_from_slice(&0u16.to_be_bytes()); // x
    msg.extend_from_slice(&0u16.to_be_bytes()); // y
    msg.extend_from_slice(&(W as u16).to_be_bytes());
    msg.extend_from_slice(&(H as u16).to_be_bytes());
    msg.extend_from_slice(&0i32.to_be_bytes()); // Raw
    for i in 0..W * H {
        let c = colour(i);
        // Little-endian 32bpp, shifts 16/8/0: bytes go out B, G, R, pad.
        msg.extend_from_slice(&[c as u8, (c >> 8) as u8, (c >> 16) as u8, 0]);
    }
    s.write_all(&msg).unwrap();

    // The client writes its frame and exits; let it close the socket first so the
    // write above is not cut short by dropping the stream.
    let mut sink = [0u8; 64];
    let _ = s.read(&mut sink);
    answered
}

/// Run the real client binary against a fake server of the given version and check the
/// frame it wrote.
fn one_frame_from(minor: u32) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let far = std::thread::spawn(move || serve_one(listener, minor));

    let out = std::env::temp_dir().join(format!("vncfree-old-{minor}.ppm"));
    let _ = std::fs::remove_file(&out);
    let status = Command::new(env!("CARGO_BIN_EXE_vncfree"))
        .arg(addr.to_string())
        .arg(&out)
        .env("VNC_PASSWORD", PASSWORD)
        .env("VNC_ENCODING", "raw")
        .env_remove("VNC_TLS")
        .env_remove("VNC_USERNAME")
        .status()
        .unwrap();
    let answered = far.join().unwrap();
    assert!(status.success(), "client exited with {status}");

    let ppm = std::fs::read(&out).unwrap();
    let header = format!("P6\n{W} {H}\n255\n");
    assert!(ppm.starts_with(header.as_bytes()), "PPM header");
    let px = &ppm[header.len()..];
    assert_eq!(px.len(), W * H * 3, "three bytes per pixel");
    for i in 0..W * H {
        let c = colour(i);
        assert_eq!(
            (px[i * 3], px[i * 3 + 1], px[i * 3 + 2]),
            ((c >> 16) as u8, (c >> 8) as u8, c as u8),
            "pixel {i} came through intact"
        );
    }
    let _ = std::fs::remove_file(&out);
    answered
}

/// 3.3 is the awkward one: no list, no answer to send back, and a client that writes
/// its choice anyway puts a stray byte where the server expects ClientInit.
#[test]
fn rfb_3_3_server_delivers_a_frame() {
    assert_eq!(one_frame_from(3), "RFB 003.003");
}

#[test]
fn rfb_3_7_server_delivers_a_frame() {
    assert_eq!(one_frame_from(7), "RFB 003.007");
}

/// The version the client has always spoken, to show the other two did not cost it.
#[test]
fn rfb_3_8_server_still_delivers_a_frame() {
    assert_eq!(one_frame_from(8), "RFB 003.008");
}

/// A server announcing something newer than we speak must be answered with our own
/// highest version, not its. Apple's Screen Sharing announces 003.889 and falls back to
/// a standard 3.8 server when answered with 003.008.
#[test]
fn a_newer_server_is_answered_with_our_own_version() {
    assert_eq!(one_frame_from(889), "RFB 003.008");
}

/// Before 3.8, a security type of None is followed by nothing at all: the next thing
/// the server expects is ClientInit. A client that waits for the SecurityResult it
/// would get from a 3.8 server waits forever, against a server waiting for it.
#[test]
fn no_security_result_follows_none_before_3_8() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let far = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(20)))
            .unwrap();
        s.write_all(b"RFB 003.003\n").unwrap();
        rd::<12>(&mut s);
        s.write_all(&1u32.to_be_bytes()).unwrap(); // None, and nothing after it
                                                   // If the client is waiting for a SecurityResult, this read times out and the
                                                   // unwrap fails the test instead of hanging it.
        assert_eq!(rd::<1>(&mut s)[0], 1, "ClientInit came straight after");
    });

    let out = std::env::temp_dir().join("vncfree-none.ppm");
    let _ = std::fs::remove_file(&out);
    // The client is killed by the server hanging up rather than exiting cleanly, so
    // only the exchange above is asserted on.
    let _ = Command::new(env!("CARGO_BIN_EXE_vncfree"))
        .arg(addr.to_string())
        .arg(&out)
        .env("VNC_PASSWORD", PASSWORD)
        .env_remove("VNC_TLS")
        .status();
    far.join().unwrap();
}

/// A failed SecurityResult carries a reason string only from 3.8. Asking an older
/// server for one blocks until it hangs up, turning a clear "wrong password" into a
/// stall, so the client has to report the failure without it.
#[test]
fn a_rejected_password_is_reported_without_a_reason_string() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let far = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(20)))
            .unwrap();
        s.write_all(b"RFB 003.007\n").unwrap();
        rd::<12>(&mut s);
        s.write_all(&[1, 2]).unwrap();
        rd::<1>(&mut s);
        s.write_all(&[7u8; 16]).unwrap();
        rd::<16>(&mut s);
        s.write_all(&1u32.to_be_bytes()).unwrap(); // failed, and no reason follows
    });

    let out = std::env::temp_dir().join("vncfree-refused.ppm");
    let _ = std::fs::remove_file(&out);
    let got = Command::new(env!("CARGO_BIN_EXE_vncfree"))
        .arg(addr.to_string())
        .arg(&out)
        .env("VNC_PASSWORD", PASSWORD)
        .env_remove("VNC_TLS")
        .output()
        .unwrap();
    far.join().unwrap();
    assert!(!got.status.success(), "the client reported a failure");
    let said = String::from_utf8_lossy(&got.stderr);
    assert!(
        said.contains("authentication failed"),
        "and said why: {said:?}"
    );
    assert!(!out.exists(), "no frame was written");
}
