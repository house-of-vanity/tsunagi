package cy.hexor.tsunagi

import android.content.Context

/** OS entry points. Network commands and all views live in the Rust library. */
internal object Native {
    init { System.loadLibrary("tsunagi_android") }
    external fun trust(context: Context)
    external fun start(service: MeshVpn, context: Context, state: String, cache: String, addresses: String): Long
    external fun failed(instance: Long): Boolean
    external fun stop(instance: Long)
    external fun disconnectExit(instance: Long, network: String, peer: String): Boolean
    external fun networkChanged(instance: Long, addresses: String)

    external fun surface()
    external fun draw(host: MeshSurface, width: Int, height: Int, density: Float): Long
    external fun touch(action: Int, id: Int, x: Float, y: Float)
    external fun input(kind: Int, value: String)
    external fun key(key: Int)
    external fun back(host: MeshSurface)
}
