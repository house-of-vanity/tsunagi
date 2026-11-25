package cy.hexor.tsunagi

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.Toast

/** Quick Settings changes the internet exit of the existing mesh agent. */
class ExitTile : TileService() {
    internal data class Target(val network: String, val peer: String, val name: String)
    private data class Snapshot(val session: Long, val active: Target?, val online: Boolean)

    companion object {
        internal fun entry(context: Context) = ComponentName(context, "${context.packageName}.OpenExit")
        private var live = Snapshot(0, null, false)
        private var pending = false
        private val main = Handler(Looper.getMainLooper())

        internal fun last(context: Context): Target? {
            val prefs = context.getSharedPreferences("exit_tile", Context.MODE_PRIVATE)
            val network = prefs.getString("network", null) ?: return null
            val peer = prefs.getString("peer", null) ?: return null
            return Target(network, peer, prefs.getString("name", null) ?: peer.take(12))
        }
        private fun refresh(context: Context) {
            requestListeningState(context, ComponentName(context, ExitTile::class.java))
        }
        internal fun publish(context: Context, session: Long, active: Target?, online: Boolean) {
            // Only confirmed agent status updates the last selection. Clearing an exit or
            // stopping the process leaves the exact network and peer available for reuse.
            if (active != null && last(context) != active) {
                context.getSharedPreferences("exit_tile", Context.MODE_PRIVATE).edit()
                    .putString("network", active.network).putString("peer", active.peer)
                    .putString("name", active.name).apply()
            }
            live = Snapshot(session, active, online)
            refresh(context)
        }
        internal fun reset(context: Context) {
            live = Snapshot(0, null, false)
            refresh(context)
        }
        internal fun restoreIfReady(context: Context, target: Target): Boolean {
            if (live.session == 0L) return false
            if (live.active == null) change(context, live.session, target, true, waitForDiscovery = true)
            return true
        }
        private fun change(context: Context, session: Long, target: Target, connect: Boolean, waitForDiscovery: Boolean = false) {
            if (pending) return
            pending = true
            refresh(context)
            val app = context.applicationContext
            Thread({
                val error = Native.tileExit(session, target.network, target.peer, connect, waitForDiscovery)
                main.post {
                    pending = false
                    if (error != null) Toast.makeText(app, error, Toast.LENGTH_LONG).show()
                    refresh(app)
                }
            }, "tsunagi-exit-tile").start()
        }
    }

    private var displayed = live
    private var remembered: Target? = null

    override fun onStartListening() {
        super.onStartListening()
        displayed = live
        remembered = last(this)
        val tile = qsTile ?: return
        val active = displayed.active
        val peer = active ?: remembered
        val subtitle = when {
            pending -> "Updating…"
            active != null && !displayed.online -> "${active.name} · offline"
            peer != null -> peer.name
            else -> "Choose exit node"
        }
        tile.state = when {
            pending -> Tile.STATE_UNAVAILABLE
            active != null -> Tile.STATE_ACTIVE
            else -> Tile.STATE_INACTIVE
        }
        tile.label = if (Build.VERSION.SDK_INT < 29 && peer != null) "Exit · ${peer.name}" else "Tsunagi Exit"
        if (Build.VERSION.SDK_INT >= 29) tile.subtitle = subtitle
        tile.contentDescription = "Tsunagi exit node, $subtitle"
        tile.updateTile()
    }

    @Suppress("DEPRECATION")
    override fun onClick() {
        super.onClick()
        if (pending || displayed != live) { onStartListening(); return }
        val target = displayed.active ?: remembered
        if (displayed.session != 0L && target != null) {
            change(this, displayed.session, target, displayed.active == null)
            return
        }
        // Consent, a stopped service, or the first selection needs an activity.
        val open = Intent().setComponent(entry(this))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 2, open, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
        } else startActivityAndCollapse(open)
    }
}
