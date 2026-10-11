//! The Android app's way into the client: the protocol engine from `vncfree::rfb`,
//! exposed to Kotlin as a handful of JNI calls. Kotlin owns the window, the touch
//! handling and the keyboard; everything that speaks RFB is the same code the Windows
//! client runs.
//!
//! Kotlin drives one session from two threads. A network thread loops `waitFrame` then
//! `copy`, and owns the session: it calls `free` when the loop ends. The UI thread sends
//! input, and calls `close` to end the session from the outside.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use jni::objects::{JIntArray, JObject, JString};
use jni::sys::{jboolean, jint, jintArray, jlong, jstring};
use jni::JNIEnv;

use vncfree::rfb::{
    key_msg, pointer_msg, send, share_monitor, typed_keys, Clip, Target, Vnc, Writer, MAX_TYPED,
};
use vncfree::Res;

struct Session {
    /// Held by the network thread for as long as it is blocked waiting on the server,
    /// which is why input goes through `w` and never through here.
    vnc: Mutex<Vnc>,
    w: Writer,
    /// A copy of the session's encodings, for asking for another monitor without
    /// waiting on `vnc`.
    encodings: Vec<i32>,
}

/// Handles Kotlin holds, looked up rather than cast from a pointer, so a key press that
/// lands after the session was freed finds nothing instead of freed memory.
static SESSIONS: Mutex<BTreeMap<jlong, Arc<Session>>> = Mutex::new(BTreeMap::new());

fn get(h: jlong) -> Res<Arc<Session>> {
    let s = SESSIONS.lock().unwrap().get(&h).cloned();
    s.ok_or_else(|| "not connected".into())
}

/// Run `f`, turning an error into an IOException on the Kotlin side.
fn throwing<T: Default>(env: &mut JNIEnv, f: impl FnOnce(&mut JNIEnv) -> Res<T>) -> T {
    f(env).unwrap_or_else(|e| {
        let _ = env.throw_new("java/io/IOException", e.to_string());
        T::default()
    })
}

fn string(env: &mut JNIEnv, s: &JString) -> Res<String> {
    Ok(env.get_string(s)?.into())
}

#[no_mangle]
pub extern "system" fn Java_net_sp00nz_vncfree_Rfb_connect(
    mut env: JNIEnv,
    _: JObject,
    addr: JString,
    user: JString,
    pass: JString,
    state: JString,
) -> jlong {
    throwing(&mut env, |env| {
        let target = Target {
            addr: string(env, &addr)?,
            user: string(env, &user)?,
            pass: string(env, &pass)?,
        };
        // The app's private files directory, for the TLS known-hosts list. Nowhere the
        // Windows default points at exists here.
        std::env::set_var("VNC_STATE", string(env, &state)?);
        // There is no mouse pointer to draw a cursor at on a touch screen, so let the
        // server paint its own into the picture.
        std::env::set_var("VNC_NO_CURSOR", "1");
        let w: Writer = Arc::default();
        let clip: Clip = Arc::default();
        let mut vnc = Vnc::connect(&target, w.clone(), clip, Arc::default())?;
        vnc.request(false)?;
        vnc.pipeline = true;
        let mut all = SESSIONS.lock().unwrap();
        let h = (1..).find(|h| !all.contains_key(h)).unwrap();
        all.insert(
            h,
            Arc::new(Session {
                encodings: vnc.encodings.clone(),
                vnc: Mutex::new(vnc),
                w,
            }),
        );
        Ok(h)
    })
}

/// Block until the screen changes, and return its size as `w << 16 | h`.
#[no_mangle]
pub extern "system" fn Java_net_sp00nz_vncfree_Rfb_waitFrame(
    mut env: JNIEnv,
    _: JObject,
    h: jlong,
) -> jint {
    throwing(&mut env, |_| {
        let s = get(h)?;
        let mut vnc = s.vnc.lock().unwrap();
        while !vnc.pump()? {}
        Ok((vnc.screen.w as jint) << 16 | vnc.screen.h as jint)
    })
}

/// Copy what the last update changed into `px` as opaque ARGB, or all of it when
/// `full` - which Kotlin asks for whenever the array is new.
#[no_mangle]
pub extern "system" fn Java_net_sp00nz_vncfree_Rfb_copy(
    mut env: JNIEnv,
    _: JObject,
    h: jlong,
    px: JIntArray,
    full: jboolean,
) {
    throwing(&mut env, |env| {
        let s = get(h)?;
        let vnc = s.vnc.lock().unwrap();
        let w = vnc.screen.w;
        let all = [(0, 0, w, vnc.screen.h)];
        let rects = if full != 0 { &all[..] } else { &vnc.dirty[..] };
        let mut row = Vec::with_capacity(w);
        for &(x, y, rw, rh) in rects {
            for line in y..y + rh {
                let o = line * w + x;
                row.clear();
                row.extend(
                    vnc.screen.px[o..o + rw]
                        .iter()
                        .map(|p| (p | 0xff00_0000) as jint),
                );
                env.set_int_array_region(&px, o as jint, &row)?;
            }
        }
        Ok(())
    })
}

/// Text the server put on its clipboard since the last call, if any.
#[no_mangle]
pub extern "system" fn Java_net_sp00nz_vncfree_Rfb_takeClipboard(
    env: JNIEnv,
    _: JObject,
    h: jlong,
) -> jstring {
    let text = get(h)
        .ok()
        .and_then(|s| s.vnc.lock().unwrap().pending_paste.take());
    match text.map(|t| env.new_string(t.replace("\r\n", "\n"))) {
        Some(Ok(j)) => j.into_raw(),
        _ => std::ptr::null_mut(),
    }
}

/// The server's monitors as `[shared, w1, h1, w2, h2, ...]`, where `shared` is the one
/// on screen (0 for all of them). Empty unless the server is vncfree-server. Called
/// from the network thread, between frames, like `takeClipboard`.
#[no_mangle]
pub extern "system" fn Java_net_sp00nz_vncfree_Rfb_monitors(
    mut env: JNIEnv,
    _: JObject,
    h: jlong,
) -> jintArray {
    throwing(&mut env, |env| {
        let s = get(h)?;
        let list: Vec<jint> = {
            let vnc = s.vnc.lock().unwrap();
            let d = &vnc.dec;
            if d.monitors.is_empty() {
                Vec::new()
            } else {
                std::iter::once(d.monitor as jint)
                    .chain(d.monitors.iter().flat_map(|&(w, h)| [w as jint, h as jint]))
                    .collect()
            }
        };
        let a = env.new_int_array(list.len() as jint)?;
        env.set_int_array_region(&a, 0, &list)?;
        Ok(a.into_raw())
    })
}

/// Share monitor `k` instead, or all of them for 0.
#[no_mangle]
pub extern "system" fn Java_net_sp00nz_vncfree_Rfb_shareMonitor(
    mut env: JNIEnv,
    _: JObject,
    h: jlong,
    k: jint,
) {
    throwing(&mut env, |_| {
        let s = get(h)?;
        share_monitor(&s.w, &s.encodings, k.max(0) as usize)
    })
}

#[no_mangle]
pub extern "system" fn Java_net_sp00nz_vncfree_Rfb_pointer(
    mut env: JNIEnv,
    _: JObject,
    h: jlong,
    mask: jint,
    x: jint,
    y: jint,
) {
    throwing(&mut env, |_| {
        send(
            &get(h)?.w,
            &pointer_msg(mask as u8, x.max(0) as u16, y.max(0) as u16),
        )
    })
}

#[no_mangle]
pub extern "system" fn Java_net_sp00nz_vncfree_Rfb_key(
    mut env: JNIEnv,
    _: JObject,
    h: jlong,
    sym: jint,
    down: jboolean,
) {
    throwing(&mut env, |_| {
        send(&get(h)?.w, &key_msg(sym as u32, down != 0))
    })
}

/// Type text, a key at a time - what the soft keyboard produces.
#[no_mangle]
pub extern "system" fn Java_net_sp00nz_vncfree_Rfb_typeText(
    mut env: JNIEnv,
    _: JObject,
    h: jlong,
    text: JString,
) {
    throwing(&mut env, |env| {
        let w = get(h)?.w.clone();
        for (sym, shift) in typed_keys(&string(env, &text)?).into_iter().take(MAX_TYPED) {
            if shift {
                send(&w, &key_msg(0xffe1, true))?; // Shift_L
            }
            send(&w, &key_msg(sym, true))?;
            send(&w, &key_msg(sym, false))?;
            if shift {
                send(&w, &key_msg(0xffe1, false))?;
            }
        }
        Ok(())
    })
}

/// End the session from the UI thread. The network thread's blocked read fails, its
/// loop ends, and it frees the session.
#[no_mangle]
pub extern "system" fn Java_net_sp00nz_vncfree_Rfb_close(_: JNIEnv, _: JObject, h: jlong) {
    shut(h);
}

#[no_mangle]
pub extern "system" fn Java_net_sp00nz_vncfree_Rfb_free(_: JNIEnv, _: JObject, h: jlong) {
    shut(h);
    SESSIONS.lock().unwrap().remove(&h);
}

fn shut(h: jlong) {
    if let Ok(s) = get(h) {
        if let Some(w) = s.w.lock().unwrap().take() {
            w.shutdown();
        }
    }
}
