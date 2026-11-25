package cy.hexor.tsunagi

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.opengl.GLSurfaceView
import android.text.InputType
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.inputmethod.BaseInputConnection
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.view.inputmethod.InputMethodManager
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.opengles.GL10

/** Surface, input connection and clipboard bridge for egui. */
class MeshSurface(private val activity: MainActivity) : GLSurfaceView(activity), GLSurfaceView.Renderer {
    private val density get() = resources.displayMetrics.density
    private val imm = activity.getSystemService(InputMethodManager::class.java)
    @Volatile private var paused = false
    private var imeMode = 0
    private var widthPx = 0
    private var heightPx = 0
    private val repaint = Runnable { requestRender() }
    private val pickExit = java.util.concurrent.atomic.AtomicBoolean()
    fun openExitPicker() { pickExit.set(true); requestRender() }
    init {
        setEGLContextClientVersion(3)
        preserveEGLContextOnPause = true
        setRenderer(this)
        renderMode = RENDERMODE_WHEN_DIRTY
        isFocusableInTouchMode = true
        requestFocus()
    }
    override fun onSurfaceCreated(gl: GL10?, config: EGLConfig?) = Native.surface(context.cacheDir.absolutePath)
    override fun onSurfaceChanged(gl: GL10?, w: Int, h: Int) { widthPx = w; heightPx = h }
    override fun onDrawFrame(gl: GL10?) {
        if (paused) return
        if (pickExit.getAndSet(false)) Native.input(6, "")
        val landscape = resources.configuration.orientation == android.content.res.Configuration.ORIENTATION_LANDSCAPE
        val delay = Native.draw(this, widthPx, heightPx, density, MeshVpn.started, landscape)
        removeCallbacks(repaint)
        postDelayed(repaint, delay.coerceAtLeast(16))
    }
    override fun onPause() {
        paused = true
        queueEvent { Native.pauseTraffic() }
        super.onPause()
        removeCallbacks(repaint)
    }
    override fun onResume() { paused = false; super.onResume(); requestRender() }
    override fun onTouchEvent(e: MotionEvent): Boolean {
        val phase = when (e.actionMasked) {
            MotionEvent.ACTION_DOWN, MotionEvent.ACTION_POINTER_DOWN -> 0
            MotionEvent.ACTION_MOVE -> 1
            MotionEvent.ACTION_UP, MotionEvent.ACTION_POINTER_UP -> 2
            MotionEvent.ACTION_CANCEL -> 3
            else -> return false
        }
        for (i in 0 until e.pointerCount) {
            if ((phase == 0 || phase == 2) && i != e.actionIndex) continue
            val id = e.getPointerId(i)
            val x = e.getX(i) / density
            val y = e.getY(i) / density
            queueEvent { Native.touch(phase, id, x, y) }
        }
        requestRender()
        return true
    }

    fun startAgent() { post { activity.requestAgent() } }
    fun stopAgent() { post { activity.stopAgent() } }
    fun requestExitNotifications() { post { activity.requestExitNotifications() } }
    fun closeScreen() { post { activity.finish() } }
    fun openUrl(url: String) { post {
        val uri = android.net.Uri.parse(url)
        if (uri.scheme == "https") {
            try { activity.startActivity(Intent(Intent.ACTION_VIEW, uri)) }
            catch (_: android.content.ActivityNotFoundException) { }
        }
    } }
    fun dispatchBack() { queueEvent { Native.back(this) }; requestRender() }
    fun copyText(value: String) { post {
        activity.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("tsunagi", value))
    } }
    fun copySecret(value: String) { post {
        val clip = ClipData.newPlainText("tsunagi", value)
        clip.description.extras = android.os.PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
        activity.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
    } }
    fun pasteSecret() { post {
        val clip = activity.getSystemService(ClipboardManager::class.java).primaryClip
        val text = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text
        if (text != null && text.length <= 2048) input(4, text.toString())
    } }
    fun keyboard(mode: Int) { post {
        imeMode = mode
        if (mode == 0) {
            imm.hideSoftInputFromWindow(windowToken, 0)
            imm.restartInput(this)
        }
        else {
            requestFocus()
            imm.restartInput(this)
            imm.showSoftInput(this, InputMethodManager.SHOW_IMPLICIT)
        }
    } }
    fun input(kind: Int, value: String) {
        queueEvent { Native.input(kind, value) }
        requestRender()
    }
    private fun key(code: Int) { queueEvent { Native.key(code) }; requestRender() }
    override fun onCheckIsTextEditor(): Boolean = imeMode != 0
    override fun onCreateInputConnection(info: EditorInfo): InputConnection? {
        if (imeMode == 0) return null
        info.inputType = InputType.TYPE_CLASS_TEXT or (if (imeMode == 2) InputType.TYPE_TEXT_VARIATION_PASSWORD else InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS)
        info.imeOptions = EditorInfo.IME_ACTION_DONE or EditorInfo.IME_FLAG_NO_EXTRACT_UI or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        return object : BaseInputConnection(this, false) {
            private var composing: String? = null
            override fun setComposingText(text: CharSequence?, newCursorPosition: Int): Boolean {
                if (composing == null) input(1, "")
                composing = text?.toString().orEmpty()
                input(2, composing.orEmpty())
                return true
            }
            override fun commitText(text: CharSequence?, newCursorPosition: Int): Boolean {
                input(if (composing == null) 0 else 3, text?.toString().orEmpty())
                composing = null
                return true
            }
            override fun finishComposingText(): Boolean {
                composing?.let { input(3, it) }
                composing = null
                return true
            }
            override fun deleteSurroundingText(before: Int, after: Int): Boolean {
                repeat(before.coerceIn(0, 2048)) { key(KeyEvent.KEYCODE_DEL) }
                repeat(after.coerceIn(0, 2048)) { key(KeyEvent.KEYCODE_FORWARD_DEL) }
                return true
            }
            override fun sendKeyEvent(event: KeyEvent): Boolean = dispatchKeyEvent(event)
            override fun performEditorAction(action: Int): Boolean { key(KeyEvent.KEYCODE_ENTER); return true }
        }
    }
    override fun onKeyDown(code: Int, event: KeyEvent): Boolean {
        when (code) {
            KeyEvent.KEYCODE_ENTER, KeyEvent.KEYCODE_TAB, KeyEvent.KEYCODE_DEL,
            KeyEvent.KEYCODE_FORWARD_DEL, KeyEvent.KEYCODE_DPAD_LEFT, KeyEvent.KEYCODE_DPAD_RIGHT -> key(code)
            else -> {
                val point = event.unicodeChar
                if (point <= 0) return super.onKeyDown(code, event)
                input(0, String(Character.toChars(point)))
            }
        }
        return true
    }
}
