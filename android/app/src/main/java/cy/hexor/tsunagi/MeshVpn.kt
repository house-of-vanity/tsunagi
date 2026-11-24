package cy.hexor.tsunagi

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.DnsResolver
import android.net.Network
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Handler
import android.os.Build
import android.os.CancellationSignal
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

class MeshVpn : VpnService() {
    companion object {
        const val STOP_VPN = "cy.hexor.tsunagi.STOP_VPN"
        private const val DISCONNECT_EXIT = "cy.hexor.tsunagi.DISCONNECT_EXIT"
        private const val NOTIFICATION_ID = 1
        private const val EXIT_CHANNEL = "exit-node"
    }
    private val main = Handler(Looper.getMainLooper())
    private val notifications by lazy { getSystemService(NotificationManager::class.java) }
    @Volatile private var instance = 0L
    private var closed = false
    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }
    @Volatile private var upstream: Network? = null
    private var watching = false
    private val changes = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = useUnderlay(network)
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            if (network == upstream && !closed) updateAddresses(properties)
        }
        override fun onLost(network: Network) {
            if (network != upstream || closed) return
            upstream = null
            // Keep the binding to the lost network until its replacement is ready.
            // Falling back to the default network here could send iroh into its own TUN.
            setUnderlyingNetworks(emptyArray())
            physicalAddresses = ""
            Native.networkChanged(instance, "")
        }
    }

    private var physicalAddresses = ""
    private fun addresses(properties: LinkProperties?) = properties?.linkAddresses.orEmpty()
        .mapNotNull { it.address.hostAddress?.substringBefore('%') }.distinct().take(32).joinToString(",")
    private fun updateAddresses(properties: LinkProperties) {
        val next = addresses(properties)
        if (next == physicalAddresses) return
        physicalAddresses = next
        Native.networkChanged(instance, next)
    }

    @Synchronized private fun useUnderlay(network: Network) {
        if (closed || !connectivity.bindProcessToNetwork(network)) return
        upstream = network
        setUnderlyingNetworks(arrayOf(network))
        physicalAddresses = addresses(connectivity.getLinkProperties(network))
        if (instance == 0L) {
            Native.trust(applicationContext)
            instance = Native.start(this, applicationContext, noBackupFilesDir.absolutePath, cacheDir.absolutePath, physicalAddresses)
        } else Native.networkChanged(instance, physicalAddresses)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            STOP_VPN -> { shutdown(); stopSelf(startId); return START_NOT_STICKY }
            DISCONNECT_EXIT -> {
                val ids = intent.data?.pathSegments.orEmpty()
                if (watching && ids.size == 2 && intent.getLongExtra("instance", 0) == instance) {
                    if (!Native.disconnectExit(instance, ids[0], ids[1])) {
                        android.widget.Toast.makeText(this, "Exit node is busy. Try again.", android.widget.Toast.LENGTH_SHORT).show()
                    }
                } else if (!watching) stopSelf(startId)
                return START_NOT_STICKY
            }
        }
        if (watching) {
            if (Native.failed(instance)) {
                Native.stop(instance)
                instance = 0
                upstream?.let(::useUnderlay)
            }
            return START_NOT_STICKY
        }
        notifications.createNotificationChannel(NotificationChannel("vpn", "VPN", NotificationManager.IMPORTANCE_LOW))
        notifications.createNotificationChannel(NotificationChannel(EXIT_CHANNEL, "Exit node", NotificationManager.IMPORTANCE_LOW))
        val startup = notification("vpn").setContentTitle("Starting mesh VPN")
        if (Build.VERSION.SDK_INT >= 31) startup.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_DEFERRED)
        startForeground(NOTIFICATION_ID, startup.build())
        watching = true
        connectivity.requestNetwork(NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), changes, Handler(Looper.getMainLooper()))
        return START_NOT_STICKY
    }

    private fun notification(channel: String): Notification.Builder {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Builder(this, channel).setSmallIcon(R.drawable.tsunagi)
            .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true).setShowWhen(false)
            .setCategory(Notification.CATEGORY_SERVICE)
    }

    // Rust publishes a change even when the activity is closed. Android holds its
    // own service binding for an established TUN, so mesh-only mode can leave
    // foreground promotion and remove the app's notification.
    fun updateExitNotification(session: Long, network: String, peer: String, title: String, text: String) {
        main.post {
            if (closed || session != instance) return@post
            if (peer.isEmpty()) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                return@post
            }
            val target = android.net.Uri.Builder().scheme("tsunagi").authority("exit")
                .appendPath(network).appendPath(peer).build()
            val disconnect = PendingIntent.getService(this, 1,
                Intent(this, MeshVpn::class.java).setAction(DISCONNECT_EXIT).setData(target).putExtra("instance", session),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val notice = notification(EXIT_CHANNEL).setContentTitle(title).setContentText(text)
                .addAction(Notification.Action.Builder(null, "Disconnect exit node", disconnect).build())
            if (Build.VERSION.SDK_INT >= 31) notice.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
            startForeground(NOTIFICATION_ID, notice.build())
        }
    }

    // Called from Rust with the exhaustive local plan; detachFd transfers ownership.
    @Synchronized fun establishTun(addresses: String, routes: String, dns: String, mtu: Int, fullTunnel: Boolean): Int {
        if (closed) return -1
        val builder = Builder().setSession("tsunagi").setMtu(mtu).setBlocking(false)
        builder.setUnderlyingNetworks(upstream?.let { arrayOf(it) } ?: emptyArray())
        addresses.split(',').forEach { builder.addAddress(it.substringBefore('/'), it.substringAfter('/').toInt()) }
        routes.split(',').forEach { builder.addRoute(it.substringBefore('/'), it.substringAfter('/').toInt()) }
        if (dns.isNotEmpty()) builder.addDnsServer(dns)
        // Mesh exits currently carry IPv4. Android blocks an unconfigured family
        // unless explicitly allowed. In split mode ordinary IPv6 should pass.
        if (!fullTunnel) builder.allowFamily(OsConstants.AF_INET6)
        return builder.establish()?.detachFd() ?: -1
    }

    // Called on a bounded Rust blocking worker, never on the UI or TUN reader.
    @android.annotation.TargetApi(29)
    fun resolveDns(query: ByteArray): ByteArray? {
        val network = upstream ?: return null
        val result = CompletableFuture<ByteArray>()
        val cancel = CancellationSignal()
        return try {
            DnsResolver.getInstance().rawQuery(network, query, DnsResolver.FLAG_EMPTY, { it.run() }, cancel,
                object : DnsResolver.Callback<ByteArray> {
                    override fun onAnswer(answer: ByteArray, rcode: Int) { result.complete(answer) }
                    override fun onError(error: DnsResolver.DnsException) { result.completeExceptionally(error) }
                })
            result.get(4, TimeUnit.SECONDS)
        } catch (_: Exception) { null } finally { cancel.cancel() }
    }

    // Android 8 and 9 expose only address lookups through their system resolver.
    fun resolveAddresses(host: String): String? = try {
        upstream?.getAllByName(host)?.mapNotNull { it.hostAddress }?.joinToString(",")
    } catch (_: java.net.UnknownHostException) { null }

    // The endpoint uses the physical network. This one explicitly selected TCP
    // socket must instead follow the same VPN as applications using the VIP.
    @Suppress("DEPRECATION")
    fun bindOverlaySocket(fd: Int, source: String): Boolean {
        val vpn = connectivity.allNetworks.firstOrNull { network ->
            connectivity.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true &&
                connectivity.getLinkProperties(network)?.linkAddresses?.any { it.address.hostAddress == source } == true
        } ?: return false
        return try {
            ParcelFileDescriptor.fromFd(fd).use { vpn.bindSocket(it.fileDescriptor) }
            true
        } catch (_: java.io.IOException) { false }
    }

    override fun onRevoke() { shutdown(); stopSelf() }
    override fun onDestroy() { shutdown(); super.onDestroy() }
    @Synchronized private fun shutdown() {
        if (closed) return
        closed = true
        if (watching) connectivity.unregisterNetworkCallback(changes)
        if (instance != 0L) Native.stop(instance)
        connectivity.bindProcessToNetwork(null)
        stopForeground(STOP_FOREGROUND_REMOVE)
    }
}
