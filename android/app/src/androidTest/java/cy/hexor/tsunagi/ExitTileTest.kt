package cy.hexor.tsunagi

import android.content.ComponentName
import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test

class ExitTileTest {
    @Test fun tileKeepsTheExactLastSelectionOnlyAfterTheAgentConfirmsIt() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val info = context.packageManager.getServiceInfo(ComponentName(context, ExitTile::class.java), 0)
        check(info.permission == "android.permission.BIND_QUICK_SETTINGS_TILE")
        check(!context.packageManager.getActivityInfo(ExitTile.entry(context), 0).exported)
        check(Native.tileExit(0, "network", "peer", true, false) == "Tsunagi Agent stopped")
        val isolated = context.createDeviceProtectedStorageContext()
        val settings = isolated.getSharedPreferences("exit_tile", Context.MODE_PRIVATE)
        settings.edit().clear().commit()
        val first = ExitTile.Target("network-a", "peer", "Gateway")
        val last = ExitTile.Target("network-b", "peer", "Gateway")
        try {
            check(ExitTile.last(isolated) == null)
            ExitTile.publish(isolated, 1L, first, true)
            ExitTile.publish(isolated, 1L, last, true)
            ExitTile.publish(isolated, 1L, null, false)
            check(ExitTile.last(isolated) == last)
            ExitTile.reset(isolated)
            check(ExitTile.last(isolated) == last)
        } finally {
            ExitTile.reset(isolated)
            settings.edit().clear().commit()
        }
    }
}
