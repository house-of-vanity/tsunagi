package cy.hexor.tsunagi

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.WindowInsets
import android.widget.FrameLayout

class MainActivity : Activity() {
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
    internal fun requestVpn() {
        val consent = VpnService.prepare(this)
        if (consent == null) startForegroundService(Intent(this, MeshVpn::class.java))
        else startActivityForResult(consent, 1)
    }
    @Deprecated("Platform consent result")
    override fun onActivityResult(request: Int, result: Int, data: Intent?) {
        super.onActivityResult(request, result, data)
        if (request == 1) {
            if (result == RESULT_OK) startForegroundService(Intent(this, MeshVpn::class.java))
            else surface.input(5, "VPN permission was declined")
        }
    }
    @Deprecated("Forward system Back to the current Rust view")
    override fun onBackPressed() { surface.dispatchBack() }
    override fun onResume() { super.onResume(); surface.onResume() }
    override fun onPause() { surface.onPause(); super.onPause() }
}
