//! The transport underneath RFB: a plain socket, or the same socket with TLS over it.
//!
//! Everything above this reads and writes through `impl Read` / `impl Write` and does
//! not care which it got.
//!
//! A `TcpStream` can be duplicated with `try_clone`, which is how both programs get an
//! independent reader and writer without a lock on the hot path. A TLS session cannot:
//! rustls keeps one connection object holding the state for both directions. So each
//! half keeps its own socket handle and they share the session behind a mutex â€” the
//! blocking wait for bytes still happens outside the lock, and only the encryption and
//! decryption are serialised. A reader parked for ten seconds on an idle screen must
//! never be able to stop the other thread sending a mouse movement.

use crate::Res;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

/// The session both halves share. `rustls::Connection` covers a client and a server
/// alike, so everything below is written once.
pub type Tls = Arc<Mutex<rustls::Connection>>;

/// rustls is built here with `ring` and nothing else, so the provider is passed
/// explicitly rather than installed into a process-wide slot. One less piece of global
/// state, and it fails to compile rather than at runtime if that ever changes.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// SHA-256 of a certificate, as pairs of hex digits, for a human to compare against the
/// same line printed at the other end.
pub fn fingerprint(der: &[u8]) -> String {
    use sha2::Digest;
    let sum = sha2::Sha256::digest(der);
    sum.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The read half. Owns its own socket handle so that the blocking read is not holding
/// the session lock.
pub struct WireRead {
    sock: TcpStream,
    tls: Option<Tls>,
    /// Ciphertext off the socket that rustls has not taken yet. It accepts only as much
    /// as it can hold at once, so one socket read can easily contain more than it will
    /// take, and throwing the remainder away corrupts the stream from that point on.
    /// The symptom is a decrypt failure some way into the session rather than anything
    /// pointing at the read that dropped the bytes.
    raw: Vec<u8>,
    raw_len: usize,
    raw_at: usize,
    /// Plaintext already decrypted and not yet handed upwards. TLS arrives in records,
    /// so one read of the socket routinely yields more than the caller asked for.
    plain: Vec<u8>,
    at: usize,
}

impl Read for WireRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let Some(tls) = self.tls.clone() else {
            return self.sock.read(out);
        };
        while self.at == self.plain.len() {
            {
                let mut c = tls.lock().unwrap();
                if self.raw_at < self.raw_len && c.wants_read() {
                    // One handful at a time. rustls refuses further ciphertext until
                    // what it already holds has been processed, so these two calls have
                    // to alternate; feeding it twice in a row fails with "message
                    // buffer full".
                    let took = c.read_tls(&mut &self.raw[self.raw_at..self.raw_len])?;
                    self.raw_at += took;
                }
                let state = c.process_new_packets().map_err(io::Error::other)?;
                let ready = state.plaintext_bytes_to_read();
                if ready > 0 {
                    self.plain.resize(ready, 0);
                    self.at = 0;
                    c.reader().read_exact(&mut self.plain)?;
                    break;
                }
                if state.peer_has_closed() {
                    return Ok(0);
                }
            }
            // Only go back to the socket once everything already in hand has been
            // handed over, or the remainder would be overwritten and lost.
            if self.raw_at == self.raw_len {
                // Deliberately outside the lock: this is where an idle session parks,
                // and it must not be holding a lock the other thread needs to send a
                // mouse movement.
                self.raw_len = self.sock.read(&mut self.raw)?;
                self.raw_at = 0;
                if self.raw_len == 0 {
                    return Ok(0);
                }
            }
        }
        let n = out.len().min(self.plain.len() - self.at);
        out[..n].copy_from_slice(&self.plain[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// The write half, with its own socket handle for the same reason.
pub struct WireWrite {
    sock: TcpStream,
    tls: Option<Tls>,
}

impl Write for WireWrite {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let Some(tls) = self.tls.clone() else {
            return self.sock.write(data);
        };
        let mut c = tls.lock().unwrap();
        let mut left = data;
        while !left.is_empty() {
            // rustls caps the plaintext it will hold - 64KB by default - and once that
            // is full it accepts nothing more. A framebuffer update is routinely larger
            // than that, so it cannot go in one call: fill the buffer, push it to the
            // socket, repeat. Handing rustls the whole frame instead fails partway with
            // "failed to write whole buffer" once per session, which reads like a
            // network fault rather than a buffer size.
            let n = c.writer().write(left)?;
            left = &left[n..];
            // The socket write stays inside the lock. Records carry a sequence number
            // and the peer rejects them out of order, so two threads that sealed
            // records under the lock and then raced to the socket would break the
            // session outright.
            let mut pushed = false;
            while c.wants_write() {
                c.write_tls(&mut self.sock)?;
                pushed = true;
            }
            if n == 0 && !pushed {
                return Err(io::Error::other("the TLS session stopped accepting data"));
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

/// Split a socket into the two halves, with no encryption.
pub fn plain(sock: TcpStream) -> Res<(WireRead, WireWrite)> {
    Ok((
        WireRead {
            sock: sock.try_clone()?,
            tls: None,
            raw: Vec::new(),
            raw_len: 0,
            raw_at: 0,
            plain: Vec::new(),
            at: 0,
        },
        WireWrite { sock, tls: None },
    ))
}

/// Drive a handshake to completion on a blocking socket.
fn shake(sock: &mut TcpStream, c: &mut rustls::Connection) -> Res<()> {
    while c.is_handshaking() {
        if c.wants_write() {
            c.write_tls(sock)?;
            continue;
        }
        if c.wants_read() {
            if c.read_tls(sock)? == 0 {
                return Err("the peer went away during the TLS handshake".into());
            }
            c.process_new_packets()?;
        }
    }
    // The handshake can leave records queued behind it; send those before the caller
    // starts writing plaintext.
    while c.wants_write() {
        c.write_tls(sock)?;
    }
    Ok(())
}

/// What the server identifies itself with, made once when it starts and used for every
/// connection after that.
///
/// The certificate is self-signed, and it is generated rather than loaded because a
/// persistent one would mean writing a private key to disk and this program
/// deliberately writes nothing. Making it once per server rather than once per
/// connection is what lets the fingerprint be printed at startup and compared: a
/// certificate regenerated for every connection would show a different fingerprint on
/// every reconnect, which is not something anyone can check against anything.
pub struct Identity {
    cfg: Arc<rustls::ServerConfig>,
    pub fingerprint: String,
}

impl Identity {
    pub fn new() -> Res<Identity> {
        let me = rcgen::generate_simple_self_signed(vec!["vncfree".to_string()])?;
        let der = me.cert.der().clone();
        let print = fingerprint(&der);
        let key = rustls::pki_types::PrivateKeyDer::try_from(me.signing_key.serialize_der())
            .map_err(|e| format!("generated an unusable private key: {e}"))?;
        let cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![der], key)?;
        Ok(Identity {
            cfg: Arc::new(cfg),
            fingerprint: print,
        })
    }
}

/// Wrap a connected socket in TLS as the server. See the note on the client's
/// certificate verifier below for what this protects against and what it does not.
pub fn server(mut sock: TcpStream, me: &Identity) -> Res<(WireRead, WireWrite)> {
    let mut c = rustls::Connection::Server(rustls::ServerConnection::new(me.cfg.clone())?);
    shake(&mut sock, &mut c)?;

    let tls = Arc::new(Mutex::new(c));
    Ok((
        WireRead {
            sock: sock.try_clone()?,
            tls: Some(tls.clone()),
            raw: vec![0; 16 * 1024],
            raw_len: 0,
            raw_at: 0,
            plain: Vec::new(),
            at: 0,
        },
        WireWrite {
            sock,
            tls: Some(tls),
        },
    ))
}

/// Accepts whatever certificate it is shown, and remembers the fingerprint.
///
/// This is not the oversight it looks like. VNC has no certificate authority and no
/// stable identity to check one against: the server is a program someone ran on a
/// desktop five minutes ago. Refusing an unsigned certificate would mean refusing every
/// server, so the alternative to trusting it is not connecting at all.
///
/// What this buys is a session nobody on the network can read, which is the whole
/// problem with VNC as it stands. What it does not buy is proof of who is on the other
/// end: someone able to sit in the middle of the connection can present their own
/// certificate and be believed. Comparing the fingerprint printed at both ends closes
/// that, and it is printed at both ends for exactly that reason.
#[derive(Debug)]
struct AcceptAny {
    provider: Arc<rustls::crypto::CryptoProvider>,
    seen: Mutex<String>,
}

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _inter: &[rustls::pki_types::CertificateDer<'_>],
        _name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self.seen.lock().unwrap() = fingerprint(end_entity);
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    // The signatures themselves are still checked properly. Skipping these would let
    // anyone replay a captured certificate they hold no key for, which is a weaker
    // position again than trusting the certificate we were shown.
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            msg,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            msg,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Wrap a connected socket in TLS as the client. Returns the halves and the server
/// certificate's fingerprint.
pub fn client(mut sock: TcpStream) -> Res<(WireRead, WireWrite, String)> {
    let p = provider();
    let verifier = Arc::new(AcceptAny {
        provider: p.clone(),
        seen: Mutex::new(String::new()),
    });
    let cfg = rustls::ClientConfig::builder_with_provider(p)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();

    // The server's certificate is self-signed with no meaningful name in it, and the
    // name is not being checked anyway, so this is only here because rustls requires
    // one.
    let name = rustls::pki_types::ServerName::try_from("vncfree")?;
    let mut c = rustls::Connection::Client(rustls::ClientConnection::new(Arc::new(cfg), name)?);
    shake(&mut sock, &mut c)?;

    let print = verifier.seen.lock().unwrap().clone();
    let tls = Arc::new(Mutex::new(c));
    Ok((
        WireRead {
            sock: sock.try_clone()?,
            tls: Some(tls.clone()),
            raw: vec![0; 16 * 1024],
            raw_len: 0,
            raw_at: 0,
            plain: Vec::new(),
            at: 0,
        },
        WireWrite {
            sock,
            tls: Some(tls),
        },
        print,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fingerprint has to be reproducible and readable, or comparing the two printed
    /// lines is not a check at all.
    #[test]
    fn a_fingerprint_is_stable_and_readable() {
        let a = fingerprint(b"some certificate");
        assert_eq!(
            a,
            fingerprint(b"some certificate"),
            "same input, same answer"
        );
        assert_ne!(a, fingerprint(b"some other certificate"));
        assert_eq!(a.len(), 32 * 3 - 1, "32 bytes as xx:xx:...");
        assert!(a
            .split(':')
            .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok()));
    }

    /// The whole point of the two halves: a reader waiting for bytes must not be able
    /// to stop the other thread writing. If the blocking read ever moves inside the
    /// session lock this deadlocks, and the failure would look like an idle session
    /// ignoring the mouse rather than anything to do with TLS.
    #[test]
    fn a_blocked_reader_does_not_stop_the_writer() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let far = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let (mut r, mut w) = server(sock, &Identity::new().unwrap()).unwrap();
            // Say nothing at first, so the client's reader is parked, then read what
            // the client sent while it was parked.
            let mut got = [0u8; 5];
            r.read_exact(&mut got).unwrap();
            w.write_all(b"pong!").unwrap();
            got
        });

        let sock = TcpStream::connect(addr).unwrap();
        let (mut r, mut w, print) = client(sock).unwrap();
        assert!(!print.is_empty(), "the client saw a certificate");

        let reader = std::thread::spawn(move || {
            let mut got = [0u8; 5];
            r.read_exact(&mut got).unwrap();
            got
        });
        // The reader above is now blocked on a server that has not spoken. This write
        // is the thing that must not be able to wait for it.
        w.write_all(b"ping!").unwrap();

        assert_eq!(&far.join().unwrap(), b"ping!");
        assert_eq!(&reader.join().unwrap(), b"pong!");
    }

    /// A framebuffer update is bigger than the plaintext rustls will buffer, so a whole
    /// frame cannot be handed over in one call. This is the size that broke the first
    /// working TLS session, and it broke it *after* a correct handshake and a correct
    /// login, which is the least helpful place for a buffer limit to show up.
    #[test]
    fn a_frame_larger_than_the_tls_buffer_goes_out_whole() {
        use std::net::TcpListener;

        let big: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
        let sent = big.clone();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let far = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let (_r, mut w) = server(sock, &Identity::new().unwrap()).unwrap();
            w.write_all(&sent).unwrap();
        });

        let sock = TcpStream::connect(addr).unwrap();
        let (mut r, _w, _) = client(sock).unwrap();
        let mut got = vec![0u8; big.len()];
        r.read_exact(&mut got).unwrap();
        assert_eq!(got, big);
        far.join().unwrap();
    }

    /// Plaintext must survive the record boundaries underneath it: one socket read can
    /// carry several messages, or half of one.
    #[test]
    fn a_message_split_across_records_reassembles() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let far = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let (_r, mut w) = server(sock, &Identity::new().unwrap()).unwrap();
            // Three separate records, which the far end asks for as one lump and then
            // as two odd-sized pieces.
            w.write_all(&[1u8; 100]).unwrap();
            w.write_all(&[2u8; 100]).unwrap();
            w.write_all(&[3u8; 100]).unwrap();
        });

        let sock = TcpStream::connect(addr).unwrap();
        let (mut r, _w, _) = client(sock).unwrap();
        let mut all = [0u8; 300];
        r.read_exact(&mut all).unwrap();
        assert!(all[..100].iter().all(|&b| b == 1));
        assert!(all[100..200].iter().all(|&b| b == 2));
        assert!(all[200..].iter().all(|&b| b == 3));
        far.join().unwrap();
    }
}
