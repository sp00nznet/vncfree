package net.sp00nz.vncfree

/**
 * The Rust side: the same RFB engine as the Windows client, in libvncfree_jni.so.
 * See android/jni/src/lib.rs. Failures arrive as IOException with the engine's own
 * message, which is written to be read by a person.
 */
object Rfb {
    init {
        System.loadLibrary("vncfree_jni")
    }

    /** Blocks through the whole handshake. Returns a session handle. */
    external fun connect(addr: String, user: String, pass: String, stateDir: String): Long

    /** Blocks until the screen changes. Returns its size as `w shl 16 or h`. */
    external fun waitFrame(h: Long): Int

    /** What the last update changed, as opaque ARGB; everything when [full]. */
    external fun copy(h: Long, px: IntArray, full: Boolean)

    external fun takeClipboard(h: Long): String?

    /** `[shared, w1, h1, w2, h2, ...]`, shared being 0 for all; empty if the server can't switch. */
    external fun monitors(h: Long): IntArray

    /** Show monitor [k] instead, numbered from 1, or all of them for 0. */
    external fun shareMonitor(h: Long, k: Int)
    external fun pointer(h: Long, mask: Int, x: Int, y: Int)
    external fun key(h: Long, sym: Int, down: Boolean)
    external fun typeText(h: Long, text: String)

    /** From any thread: ends the session, which unblocks [waitFrame]. */
    external fun close(h: Long)

    /** Only from the thread that called [waitFrame], once it has returned for good. */
    external fun free(h: Long)
}
