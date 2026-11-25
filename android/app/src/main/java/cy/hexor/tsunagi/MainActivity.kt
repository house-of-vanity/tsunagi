package cy.hexor.tsunagi

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.WindowInsets
import android.widget.FrameLayout

class MainActivity : Activity() {
    private val settings by lazy { getSharedPreferences("agent", MODE_PRIVATE) }
    private var checkedAutoStart = false
    private var consentPending = false
    private var askedForNotifications = false
    internal fun requestExitNotifications() {
        if (Build.VERSION.SDK_INT >= 33 && !askedForNotifications &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            askedForNotifications = true
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 2)
        }
    }
    private lateinit var surface: MeshSurface
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        consentPending = savedInstanceState?.getBoolean("consent_pending") == true
        surface = MeshSurface(this)
        val root = FrameLayout(this)
        if (Build.VERSION.SDK_INT >= 30) {
            window.setDecorFitsSystemWindows(false)
            root.setOnApplyWindowInsetsListener { view, insets ->
                val area = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout() or WindowInsets.Type.ime())
                view.setPadding(area.left, area.top, area.right, area.bottom)
                insets
            }
        } else root.fitsSystemWindows = true
        root.addView(surface)
        setContentView(root)
    }
    override fun onPostResume() {
        super.onPostResume()
        if (checkedAutoStart) return
        checkedAutoStart = true
        if (!MeshVpn.started && settings.getBoolean("auto_start", true)) requestAgent()
    }
    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean("consent_pending", consentPending)
    }
    internal fun requestAgent() {
        if (consentPending) return
        val consent = VpnService.prepare(this)
        if (consent == null) startAgent() else {
            consentPending = true
            startActivityForResult(consent, 1)
        }
    }
    private fun startAgent() {
        settings.edit().putBoolean("auto_start", true).apply()
        val service = Intent(this, MeshVpn::class.java)
        // A retry of an existing service may already have left foreground mode.
        if (MeshVpn.started) startService(service) else startForegroundService(service)
    }
    internal fun stopAgent() {
        settings.edit().putBoolean("auto_start", false).apply()
        startService(Intent(this, MeshVpn::class.java).setAction(MeshVpn.STOP_VPN))
    }
    @Deprecated("Platform consent result")
    override fun onActivityResult(request: Int, result: Int, data: Intent?) {
        super.onActivityResult(request, result, data)
        if (request == 1) {
            consentPending = false
            if (result == RESULT_OK) startAgent() else {
                settings.edit().putBoolean("auto_start", false).apply()
                surface.input(5, "Android VPN permission was declined")
            }
        }
    }
    @Deprecated("Forward system Back to the current Rust view")
    override fun onBackPressed() { surface.dispatchBack() }
    override fun onResume() { super.onResume(); surface.onResume() }
    override fun onPause() { surface.onPause(); super.onPause() }
}
