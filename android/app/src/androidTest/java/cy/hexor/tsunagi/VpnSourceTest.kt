package cy.hexor.tsunagi

import android.content.Context
import android.content.ContextWrapper
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test

class VpnSourceTest {
    private external fun checkSockets(fd: Int, networkCount: Int)

    @Test fun udpAndPingReceiveFromBothNetworksAfterAddingTheSecond() {
        System.loadLibrary("vpn_source_probe")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        check(VpnService.prepare(context) == null) { "Grant VPN consent on the test emulator first" }
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        // Android requires the manifest-declared service class. Attach it under the
        // application UID without starting the agent and binding this process to the underlay.
        val vpn = MeshVpn()
        ContextWrapper::class.java.getDeclaredMethod("attachBaseContext", Context::class.java)
            .apply { isAccessible = true }.invoke(vpn, context)
        MeshVpn::class.java.getDeclaredField("upstream").apply { isAccessible = true }
            .set(vpn, connectivity.activeNetwork)
        val hosts = listOf("198.18.234.1/24", "198.19.234.1/24")
        val routes = listOf("198.18.234.0/24", "198.19.234.0/24")
        fun establish(count: Int): ParcelFileDescriptor {
            val fd = vpn.establishTun(hosts.take(count).joinToString(","),
                routes.take(count).joinToString(","), "", 1280, false)
            check(fd >= 0) { "VPN establishment failed" }
            return ParcelFileDescriptor.adoptFd(fd)
        }
        fun checkVpn(fd: ParcelFileDescriptor, count: Int) {
            val deadline = SystemClock.elapsedRealtime() + 5000
            while (true) {
                val active = connectivity.activeNetwork
                if (connectivity.getNetworkCapabilities(active)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                    && connectivity.getLinkProperties(active)?.linkAddresses?.size == count) break
                check(SystemClock.elapsedRealtime() < deadline) { "Timed out waiting for VPN routes" }
                SystemClock.sleep(25)
            }
            checkSockets(ParcelFileDescriptor.dup(fd.fileDescriptor).detachFd(), count)
        }
        establish(1).use { first ->
            checkVpn(first, 1)
            establish(2).use { both -> checkVpn(both, 2) }
        }
    }
}
