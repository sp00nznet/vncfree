//! Continuous updates, driven against the real client binary.
//!
//! The point of this feature is a message that stops being sent, which is exactly the
//! kind of thing a frame-rate measurement cannot see: on loopback the round trip it
//! removes costs nothing, so the win only appears on a link with real latency. What can
//! be checked here is the mechanism — that the client asks for it, and then accepts a
//! frame it never requested.
//!
//! There is also no field anywhere that advertises server support. An unprompted
//! EndOfContinuousUpdates *is* the announcement, so the exact byte exchange below is the
//! whole contract and worth pinning.

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

/// A full-screen Raw update, as a server that was never asked would send it.
fn one_frame() -> Vec<u8> {
    let mut msg = vec![0u8, 0];
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&(W as u16).to_be_bytes());
    msg.extend_from_slice(&(H as u16).to_be_bytes());
    msg.extend_from_slice(&0i32.to_be_bytes());
    for i in 0..W * H {
        msg.extend_from_slice(&[i as u8, 0x40, 0x80, 0]); // B, G, R, pad
    }
    msg
}

struct Seen {
    encodings: Vec<i32>,
    enable: Vec<u8>,
    requests_before_enable: usize,
}

fn serve(listener: TcpListener) -> Seen {
    let (mut s, _) = listener.accept().unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();

    s.write_all(b"RFB 003.008\n").unwrap();
    rd::<12>(&mut s);
    s.write_all(&[1, 2]).unwrap();
    assert_eq!(rd::<1>(&mut s)[0], 2);
    let challenge = [7u8; 16];
    s.write_all(&challenge).unwrap();
    let answer = rd::<16>(&mut s);
    let mut expected = challenge;
    vncfree::vnc_des(&mut expected, PASSWORD);
    assert_eq!(answer, expected);
    s.write_all(&0u32.to_be_bytes()).unwrap();

    assert_eq!(rd::<1>(&mut s)[0], 1, "ClientInit");
    let name = b"pusher";
    let mut init = Vec::new();
    init.extend_from_slice(&(W as u16).to_be_bytes());
    init.extend_from_slice(&(H as u16).to_be_bytes());
    init.extend_from_slice(&vncfree::PIXEL_FORMAT);
    init.extend_from_slice(&(name.len() as u32).to_be_bytes());
    init.extend_from_slice(name);
    s.write_all(&init).unwrap();

    let mut seen = Seen {
        encodings: Vec::new(),
        enable: Vec::new(),
        requests_before_enable: 0,
    };
    let mut announced = false;
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
                seen.encodings = list
                    .chunks(4)
                    .map(|c| i32::from_be_bytes(c.try_into().unwrap()))
                    .collect();
                // The announcement: unprompted, and the only way to offer this.
                s.write_all(&[150]).unwrap();
                announced = true;
            }
            3 => {
                rd::<9>(&mut s);
                if !announced || seen.enable.is_empty() {
                    seen.requests_before_enable += 1;
                }
            }
            150 => {
                // EnableContinuousUpdates: the flag and the region it wants.
                seen.enable = rd::<9>(&mut s).to_vec();
                break;
            }
            other => panic!("unexpected client message type {other}"),
        }
    }

    // Now send a frame nobody asked for. Under the old rules this would be a protocol
    // violation and the client would be within its rights to ignore it.
    s.write_all(&one_frame()).unwrap();
    let mut sink = [0u8; 64];
    let _ = s.read(&mut sink);
    seen
}

#[test]
fn the_client_asks_for_updates_it_then_stops_requesting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let far = std::thread::spawn(move || serve(listener));

    let out = std::env::temp_dir().join("vncfree-continuous.ppm");
    let _ = std::fs::remove_file(&out);
    let status = Command::new(env!("CARGO_BIN_EXE_vncfree"))
        .arg(addr.to_string())
        .arg(&out)
        .env("VNC_PASSWORD", PASSWORD)
        .env("VNC_ENCODING", "raw")
        .env_remove("VNC_TLS")
        .env_remove("VNC_NO_CONTINUOUS")
        .status()
        .unwrap();
    let seen = far.join().unwrap();
    assert!(status.success(), "client exited with {status}");

    assert!(
        seen.encodings.contains(&-313),
        "the client offered continuous updates: {:?}",
        seen.encodings
    );
    assert_eq!(seen.enable[0], 1, "enable, not disable");
    assert_eq!(
        &seen.enable[1..],
        &[0, 0, 0, 0, 0, W as u8, 0, H as u8],
        "for the whole screen"
    );
    // One full-screen request at the start is expected and stays: continuous updates
    // send *changes*, so something still has to ask for the first picture.
    assert!(
        seen.requests_before_enable <= 1,
        "asked {} times before enabling",
        seen.requests_before_enable
    );

    // And the unrequested frame arrived and decoded.
    let ppm = std::fs::read(&out).unwrap();
    let header = format!("P6\n{W} {H}\n255\n");
    assert!(ppm.starts_with(header.as_bytes()));
    let px = &ppm[header.len()..];
    for i in 0..W * H {
        assert_eq!(
            (px[i * 3], px[i * 3 + 1], px[i * 3 + 2]),
            (0x80, 0x40, i as u8),
            "pixel {i} of the frame nobody asked for"
        );
    }
    let _ = std::fs::remove_file(&out);
}

/// The safety valve, for a server that mishandles them. Same shape as VNC_NO_PIPELINE,
/// and worth having for the same reason: this changes who is allowed to speak first.
#[test]
fn vnc_no_continuous_declines_the_offer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let far = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(20)))
            .unwrap();
        s.write_all(b"RFB 003.008\n").unwrap();
        rd::<12>(&mut s);
        s.write_all(&[1, 2]).unwrap();
        rd::<1>(&mut s);
        s.write_all(&[7u8; 16]).unwrap();
        rd::<16>(&mut s);
        s.write_all(&0u32.to_be_bytes()).unwrap();
        rd::<1>(&mut s);
        let name = b"pusher";
        let mut init = Vec::new();
        init.extend_from_slice(&(W as u16).to_be_bytes());
        init.extend_from_slice(&(H as u16).to_be_bytes());
        init.extend_from_slice(&vncfree::PIXEL_FORMAT);
        init.extend_from_slice(&(name.len() as u32).to_be_bytes());
        init.extend_from_slice(name);
        s.write_all(&init).unwrap();

        let mut enabled = false;
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
                    s.write_all(&[150]).unwrap();
                }
                3 => {
                    rd::<9>(&mut s);
                    // It asked the old way, which is the whole point.
                    s.write_all(&one_frame()).unwrap();
                    break;
                }
                150 => {
                    rd::<9>(&mut s);
                    enabled = true;
                    break;
                }
                other => panic!("unexpected client message type {other}"),
            }
        }
        let mut sink = [0u8; 64];
        let _ = s.read(&mut sink);
        enabled
    });

    let out = std::env::temp_dir().join("vncfree-nocontinuous.ppm");
    let _ = std::fs::remove_file(&out);
    let status = Command::new(env!("CARGO_BIN_EXE_vncfree"))
        .arg(addr.to_string())
        .arg(&out)
        .env("VNC_PASSWORD", PASSWORD)
        .env("VNC_ENCODING", "raw")
        .env("VNC_NO_CONTINUOUS", "1")
        .env_remove("VNC_TLS")
        .status()
        .unwrap();
    let enabled = far.join().unwrap();
    assert!(status.success(), "client exited with {status}");
    assert!(
        !enabled,
        "the offer was declined and the client kept asking"
    );
    let _ = std::fs::remove_file(&out);
}
