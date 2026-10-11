package net.sp00nz.vncfree

import android.app.Activity
import android.content.ClipboardManager
import android.view.KeyEvent as AKey
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.calculateCentroid
import androidx.compose.foundation.gestures.calculatePan
import androidx.compose.foundation.gestures.calculateZoom
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isAltPressed
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isMetaPressed
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

@Composable
fun Connect(vm: Vm) {
    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.safeDrawingPadding().imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("vncfree", style = MaterialTheme.typography.headlineMedium)
            OutlinedTextField(
                vm.address, { vm.address = it }, Modifier.fillMaxWidth(),
                label = { Text("Address") }, placeholder = { Text("host or host:port") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Next),
            )
            OutlinedTextField(
                vm.username, { vm.username = it }, Modifier.fillMaxWidth(),
                label = { Text("Username") }, supportingText = { Text("Only for a Mac - leave blank otherwise") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
            )
            OutlinedTextField(
                vm.password, { vm.password = it }, Modifier.fillMaxWidth(),
                label = { Text("Password") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Go),
                keyboardActions = KeyboardActions(onGo = { if (vm.address.isNotBlank()) vm.connect() }),
            )
            vm.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            // Greyed out until there is an address: a placeholder that gets left in
            // place spends ten seconds timing out against a host that does not exist.
            Button({ vm.connect() }, enabled = vm.address.isNotBlank() && !vm.connecting) {
                if (vm.connecting) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                else Text("Connect")
            }
            Spacer(Modifier.height(24.dp))
            Text(
                "Free forever, MIT licensed, no telemetry, no account. If anyone tries to " +
                    "sell you this, walk away.\nv${BuildConfig.VERSION_NAME} - github.com/sp00nznet/vncfree",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** RFB button mask bits. */
private const val LEFT = 1
private const val RIGHT = 4

/**
 * The remote screen. One finger is the mouse: tap clicks, hold-and-release
 * right-clicks, drag drags. Two fingers zoom and pan the view, and never reach the
 * remote machine.
 */
@Composable
fun Remote(vm: Vm) {
    FullScreen()

    // Back to the whole picture whenever it becomes a different monitor.
    val shown = vm.monitors.firstOrNull()
    var zoom by remember(shown) { mutableFloatStateOf(1f) }
    var pan by remember(shown) { mutableStateOf(Offset.Zero) }
    var view by remember { mutableStateOf(IntSize.Zero) }
    val focus = remember { FocusRequester() }
    val keyboard = LocalSoftwareKeyboardController.current
    val context = LocalContext.current

    // Where the framebuffer sits in the view: fitted, then zoomed and panned.
    fun scale(fw: Int, fh: Int) = min(view.width / fw.toFloat(), view.height / fh.toFloat()) * zoom
    fun origin(fw: Int, fh: Int, s: Float) =
        Offset((view.width - fw * s) / 2, (view.height - fh * s) / 2) + pan

    // Modifiers latched from the key strip. They go down on the remote machine when
    // tapped and come back up after the next key, from the strip or the soft keyboard,
    // which is how Ctrl+C gets typed on a keyboard that has no Ctrl.
    val held = remember { mutableStateListOf<Int>() }
    var strip by remember { mutableStateOf(false) }
    fun release() {
        held.forEach { s -> vm.send { Rfb.key(it, s, false) } }
        held.clear()
    }
    fun press(sym: Int) {
        vm.send { Rfb.key(it, sym, true); Rfb.key(it, sym, false) }
        release()
    }
    // The server cannot tell a key lifted from one forgotten, so a modifier still
    // latched when the session ends would stay held down on the remote machine.
    BackHandler { release(); vm.disconnect() }
    fun latch(sym: Int) {
        val down = sym !in held
        if (down) held += sym else held -= sym
        vm.send { Rfb.key(it, sym, down) }
    }

    Column(Modifier.fillMaxSize().background(Color.Black).imePadding()) {
        Row(Modifier.fillMaxWidth().background(BAR), horizontalArrangement = Arrangement.SpaceEvenly) {
            val tool = @Composable { label: String, onClick: () -> Unit ->
                TextButton(onClick) { Text(label, color = Color.White) }
            }
            tool("Keyboard") { focus.requestFocus(); keyboard?.show() }
            tool(if (strip) "Hide keys" else "PC keys") { strip = !strip }
            // Only a vncfree server can switch, and only with more than one to show.
            if (vm.monitors.size > 3) Box {
                var open by remember { mutableStateOf(false) }
                tool(if (shown == 0) "All screens" else "Screen $shown") { open = true }
                DropdownMenu(open, { open = false }) {
                    val n = (vm.monitors.size - 1) / 2
                    for (k in (1..n) + 0) {
                        val label = if (k == 0) "All screens"
                        else "Screen $k - ${vm.monitors[2 * k - 1]}x${vm.monitors[2 * k]}"
                        DropdownMenuItem({ Text(label) }, { open = false; vm.send { Rfb.shareMonitor(it, k) } })
                    }
                }
            }
            // Typed rather than put on the remote clipboard, because a Mac has no
            // clipboard over VNC at all and typing works on everything.
            tool("Paste") {
                val text = context.getSystemService(ClipboardManager::class.java)
                    .primaryClip?.getItemAt(0)?.coerceToText(context)?.toString()
                if (!text.isNullOrEmpty()) vm.send { Rfb.typeText(it, text) }
            }
            tool("Close") { release(); vm.disconnect() }
        }

        Box(Modifier.weight(1f).fillMaxWidth()) {
            KeyCatcher(vm, focus, ::press, ::release)
            Canvas(
                Modifier.fillMaxSize()
                    .onSizeChanged { view = it }
                    .pointerInput(vm.session) {
                        awaitEachGesture {
                            val first = awaitFirstDown()
                            val bmp = vm.frame ?: return@awaitEachGesture
                            val (fw, fh) = bmp.width to bmp.height
                            fun at(p: Offset): Pair<Int, Int> {
                                val s = scale(fw, fh)
                                val o = origin(fw, fh, s)
                                return ((p.x - o.x) / s).roundToInt().coerceIn(0, fw - 1) to
                                    ((p.y - o.y) / s).roundToInt().coerceIn(0, fh - 1)
                            }
                            fun mouse(mask: Int, p: Offset) = at(p).let { (x, y) -> vm.send { Rfb.pointer(it, mask, x, y) } }

                            val longAt = first.uptimeMillis + viewConfiguration.longPressTimeoutMillis
                            var mode = 0 // 0 undecided, 1 dragging, 2 two fingers
                            while (true) {
                                val ev = awaitPointerEvent()
                                val down = ev.changes.filter { it.pressed }
                                if (down.isEmpty()) {
                                    val last = ev.changes.first()
                                    when (mode) {
                                        0 -> {
                                            val button = if (last.uptimeMillis >= longAt) RIGHT else LEFT
                                            mouse(button, first.position)
                                            mouse(0, first.position)
                                        }
                                        1 -> mouse(0, last.position)
                                    }
                                    break
                                }
                                if (down.size > 1 && mode == 0) mode = 2
                                when (mode) {
                                    2 -> {
                                        // Zoom about the point between the fingers, so
                                        // what is under them stays under them.
                                        val c = ev.calculateCentroid()
                                        val s0 = scale(fw, fh)
                                        val under = (c - origin(fw, fh, s0)) / s0
                                        zoom = (zoom * ev.calculateZoom()).coerceIn(1f, 8f)
                                        val s1 = scale(fw, fh)
                                        val centred = Offset((view.width - fw * s1) / 2, (view.height - fh * s1) / 2)
                                        val p = c - under * s1 - centred + ev.calculatePan()
                                        // Never further than the edge of the picture.
                                        val mx = max(0f, (fw * s1 - view.width) / 2)
                                        val my = max(0f, (fh * s1 - view.height) / 2)
                                        pan = Offset(p.x.coerceIn(-mx, mx), p.y.coerceIn(-my, my))
                                    }
                                    1 -> mouse(LEFT, down[0].position)
                                    0 -> if ((down[0].position - first.position).getDistance() > viewConfiguration.touchSlop) {
                                        mode = 1
                                        mouse(LEFT, first.position)
                                        mouse(LEFT, down[0].position)
                                    }
                                }
                                ev.changes.forEach { it.consume() }
                            }
                        }
                    }
            ) {
                vm.frames // read, so each new frame redraws
                val bmp = vm.frame ?: return@Canvas
                val s = scale(bmp.width, bmp.height)
                val o = origin(bmp.width, bmp.height, s)
                drawImage(
                    bmp.asImageBitmap(),
                    dstOffset = IntOffset(o.x.roundToInt(), o.y.roundToInt()),
                    dstSize = IntSize((bmp.width * s).roundToInt(), (bmp.height * s).roundToInt()),
                    filterQuality = FilterQuality.Low,
                )
            }
        }

        // Docked at the bottom, so it sits on top of the soft keyboard when that is up.
        if (strip) Column(Modifier.fillMaxWidth().background(BAR)) {
            for (row in STRIP) Row(Modifier.horizontalScroll(rememberScrollState())) {
                for ((label, sym) in row) {
                    val latched = sym in held
                    Text(
                        label,
                        Modifier.padding(2.dp).clip(RoundedCornerShape(6.dp))
                            .background(if (latched) MaterialTheme.colorScheme.primary else Color(0xFF3C4043))
                            .clickable { if (sym in MODIFIERS) latch(sym) else press(sym) }
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        color = Color.White,
                    )
                }
            }
        }
    }
}

private val BAR = Color(0xFF202124)
private val MODIFIERS = setOf(0xffe1, 0xffe3, 0xffe9, 0xffeb)

/** The keys a PC keyboard has and a phone keyboard does not, as label to X keysym. */
private val STRIP = listOf(
    listOf(
        "Esc" to 0xff1b, "Tab" to 0xff09, "Ctrl" to 0xffe3, "Alt" to 0xffe9, "Shift" to 0xffe1,
        // macOS Screen Sharing maps Super onto Command, as on the Windows client.
        "Win/Cmd" to 0xffeb, "←" to 0xff51, "↑" to 0xff52, "↓" to 0xff54, "→" to 0xff53,
    ),
    listOf(
        "Home" to 0xff50, "End" to 0xff57, "PgUp" to 0xff55, "PgDn" to 0xff56,
        "Ins" to 0xff63, "Del" to 0xffff, "PrtSc" to 0xff61, "Menu" to 0xff67,
    ),
    (1..12).map { "F$it" to 0xffbd + it },
)

/**
 * An invisible text field that holds focus for the whole session, because that is
 * the only way to receive both the soft keyboard and a hardware one.
 *
 * Text arrives as edits against a one-space sentinel: anything after it was typed, and
 * the sentinel going missing was a backspace. Keys that are not text - arrows, Escape,
 * and anything with Ctrl or Alt held - are caught before the field sees them.
 */
@Composable
private fun KeyCatcher(vm: Vm, focus: FocusRequester, tap: (Int) -> Unit, release: () -> Unit) {
    val sentinel = TextFieldValue(" ", TextRange(1))
    var value by remember { mutableStateOf(sentinel) }
    LaunchedEffect(Unit) { focus.requestFocus() }
    BasicTextField(
        value,
        onValueChange = { v ->
            when {
                v.text.isEmpty() -> tap(0xff08) // BackSpace
                v.text.length > 1 -> { vm.send { Rfb.typeText(it, v.text.substring(1)) }; release() }
            }
            value = sentinel
        },
        modifier = Modifier.size(1.dp).focusRequester(focus).onPreviewKeyEvent { e ->
            val native = e.nativeKeyEvent
            val sym = KEYSYMS[native.keyCode]
                ?: if (e.isCtrlPressed || e.isAltPressed || e.isMetaPressed) native.getUnicodeChar(0).takeIf { it > 0 }
                else null
            if (sym == null) return@onPreviewKeyEvent false
            vm.send { Rfb.key(it, sym, e.type == KeyEventType.KeyDown) }
            true
        },
        // Password: the one keyboard type on which IMEs reliably stop composing words
        // and second-guessing them, so each key arrives as it is pressed.
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Password, autoCorrectEnabled = false, imeAction = ImeAction.Send,
        ),
        keyboardActions = KeyboardActions(onSend = { tap(0xff0d) }), // Return
        singleLine = true,
    )
}

/** Android key code to X keysym, for keys that are not text. */
private val KEYSYMS = buildMap {
    put(AKey.KEYCODE_DEL, 0xff08)
    put(AKey.KEYCODE_FORWARD_DEL, 0xffff)
    put(AKey.KEYCODE_ENTER, 0xff0d)
    put(AKey.KEYCODE_NUMPAD_ENTER, 0xff8d)
    put(AKey.KEYCODE_TAB, 0xff09)
    put(AKey.KEYCODE_ESCAPE, 0xff1b)
    put(AKey.KEYCODE_MOVE_HOME, 0xff50)
    put(AKey.KEYCODE_DPAD_LEFT, 0xff51)
    put(AKey.KEYCODE_DPAD_UP, 0xff52)
    put(AKey.KEYCODE_DPAD_RIGHT, 0xff53)
    put(AKey.KEYCODE_DPAD_DOWN, 0xff54)
    put(AKey.KEYCODE_PAGE_UP, 0xff55)
    put(AKey.KEYCODE_PAGE_DOWN, 0xff56)
    put(AKey.KEYCODE_MOVE_END, 0xff57)
    put(AKey.KEYCODE_INSERT, 0xff63)
    put(AKey.KEYCODE_SHIFT_LEFT, 0xffe1)
    put(AKey.KEYCODE_SHIFT_RIGHT, 0xffe2)
    put(AKey.KEYCODE_CTRL_LEFT, 0xffe3)
    put(AKey.KEYCODE_CTRL_RIGHT, 0xffe4)
    put(AKey.KEYCODE_ALT_LEFT, 0xffe9)
    put(AKey.KEYCODE_ALT_RIGHT, 0xffea)
    // macOS Screen Sharing maps Super onto Command, as on the Windows client.
    put(AKey.KEYCODE_META_LEFT, 0xffeb)
    put(AKey.KEYCODE_META_RIGHT, 0xffec)
    for (i in 0 until 12) put(AKey.KEYCODE_F1 + i, 0xffbe + i)
}

/** System bars hidden and the screen kept on, for as long as a session is showing. */
@Composable
private fun FullScreen() {
    val view = LocalView.current
    DisposableEffect(view) {
        val window = (view.context as Activity).window
        val bars = WindowCompat.getInsetsController(window, view)
        bars.systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        bars.hide(WindowInsetsCompat.Type.systemBars())
        view.keepScreenOn = true
        onDispose {
            bars.show(WindowInsetsCompat.Type.systemBars())
            view.keepScreenOn = false
        }
    }
}
