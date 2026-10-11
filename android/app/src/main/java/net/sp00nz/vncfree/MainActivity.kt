package net.sp00nz.vncfree

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.graphics.Bitmap
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.edit
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import java.io.IOException
import kotlin.concurrent.thread

/**
 * The connection and everything on screen about it.
 *
 * ponytail: no navigation library, no DI. Connected or not is the whole navigation.
 */
class Vm(private val app: Application) : AndroidViewModel(app) {

    private val prefs = app.getSharedPreferences("vncfree", 0)
    private val main = Handler(Looper.getMainLooper())

    // Address and username are remembered; the password never is. Same as the Windows
    // client, which writes nothing but the TLS known-hosts list.
    var address by mutableStateOf(prefs.getString("address", "")!!)
    var username by mutableStateOf(prefs.getString("username", "")!!)
    var password by mutableStateOf("")

    var connecting by mutableStateOf(false)
    var error by mutableStateOf<String?>(null)

    /** The live session's handle, or 0. */
    var session by mutableLongStateOf(0L)
    var frame by mutableStateOf<Bitmap?>(null)

    /** Bumped per frame so the screen redraws: the bitmap object alone may not change. */
    var frames by mutableIntStateOf(0)

    /** As [Rfb.monitors] says: which is shown, then each one's size. */
    var monitors by mutableStateOf(IntArray(0))
    private var closing = false

    fun connect() {
        // host alone means the default VNC port, which is what anyone typing an address
        // into a phone means. ponytail: a bare IPv6 address needs [brackets]:port
        val addr = address.trim().let { if (':' in it) it else "$it:5900" }
        prefs.edit { putString("address", address.trim()).putString("username", username.trim()) }
        connecting = true
        error = null
        closing = false
        val (user, pass) = username.trim() to password
        thread(name = "vnc") {
            val h = try {
                Rfb.connect(addr, user, pass, app.filesDir.path)
            } catch (e: IOException) {
                main.post { connecting = false; error = e.message }
                return@thread
            }
            main.post { connecting = false; session = h }
            run(h)
        }
    }

    /** The network loop: one frame per pass, until the link drops or [disconnect]. */
    private fun run(h: Long) {
        var px = IntArray(0)
        // Two bitmaps, alternated, so the one being drawn is never the one being
        // written. ponytail: a draw slower than two whole frames could still tear one.
        val bitmaps = arrayOfNulls<Bitmap>(2)
        var which = 0
        try {
            while (true) {
                val size = Rfb.waitFrame(h)
                val (w, ht) = (size ushr 16) to (size and 0xffff)
                val fresh = px.size != w * ht
                if (fresh) {
                    px = IntArray(w * ht)
                    for (i in bitmaps.indices) bitmaps[i] = Bitmap.createBitmap(w, ht, Bitmap.Config.ARGB_8888)
                }
                Rfb.copy(h, px, fresh)
                which = which xor 1
                val bmp = bitmaps[which]!!
                bmp.setPixels(px, 0, w, 0, 0, w, ht)
                val clip = Rfb.takeClipboard(h)
                val mons = Rfb.monitors(h)
                main.post {
                    if (!mons.contentEquals(monitors)) monitors = mons
                    frame = bmp
                    frames++
                    if (clip != null) {
                        app.getSystemService(ClipboardManager::class.java)
                            .setPrimaryClip(ClipData.newPlainText("vncfree", clip))
                    }
                }
            }
        } catch (e: IOException) {
            main.post { if (!closing) error = "Disconnected: ${e.message}" }
        } finally {
            Rfb.free(h)
            main.post { session = 0; frame = null; monitors = IntArray(0) }
        }
    }

    fun disconnect() {
        closing = true
        Rfb.close(session)
    }

    /** Input from the UI thread. A failure means the link is going; the loop says so. */
    fun send(f: (Long) -> Unit) {
        try {
            if (session != 0L) f(session)
        } catch (_: IOException) {
        }
    }

    override fun onCleared() = disconnect()
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                val vm: Vm = viewModel()
                if (vm.session != 0L) Remote(vm) else Connect(vm)
            }
        }
    }
}
