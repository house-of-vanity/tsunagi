package cy.hexor.tsunagi

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test

class AgentStartupTest {
    @Suppress("DEPRECATION")
    @Test fun launchStartsAgentAndExplicitStopSurvivesReopening() {
        val test = InstrumentationRegistry.getInstrumentation()
        val context = test.targetContext
        check(VpnService.prepare(context) == null) { "Grant VPN consent on the test emulator first" }
        val manager = context.getSystemService(ActivityManager::class.java)
        fun running() = manager.getRunningServices(Int.MAX_VALUE).any {
            it.service.className == MeshVpn::class.java.name && it.started
        }
        fun awaitRunning(expected: Boolean) {
            val deadline = SystemClock.elapsedRealtime() + 5000
            while (running() != expected) {
                check(SystemClock.elapsedRealtime() < deadline) { "Agent did not reach started=$expected" }
                SystemClock.sleep(25)
            }
        }
        fun launch() = test.startActivitySync(Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as MainActivity

        val settings = context.getSharedPreferences("agent", Context.MODE_PRIVATE)
        val old = settings.getBoolean("auto_start", true)
        var activity: MainActivity? = null
        try {
            settings.edit().remove("auto_start").commit()
            activity = launch()
            awaitRunning(true)
            test.runOnMainSync { activity!!.stopAgent(); activity!!.finish() }
            awaitRunning(false)
            activity = launch()
            test.waitForIdleSync()
            check(!running())
            test.runOnMainSync { activity!!.requestAgent() }
            awaitRunning(true)
        } finally {
            test.runOnMainSync { activity?.stopAgent(); activity?.finish() }
            awaitRunning(false)
            settings.edit().putBoolean("auto_start", old).commit()
        }
    }
}
