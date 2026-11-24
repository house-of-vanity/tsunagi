# Android client

Open this directory in Android Studio. The debug prototype targets ARM64 devices running Android 8 or later with OpenGL ES 3. Install SDK Platform 35 and the NDK with the SDK Manager. Point `ANDROID_HOME` at your SDK and `ANDROID_NDK_HOME` at the installed NDK directory. The Gradle launcher needs a JDK, such as the one bundled with Android Studio.

From the repository root, with Cargo and cargo-ndk on your PATH:

```sh
rustup target add aarch64-linux-android
cargo install cargo-ndk --version 4.1.2 --locked
cd android
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Open **tsunagi**, tap **Start VPN**, accept Android’s VPN prompt, then join with the existing network name and secret. Android keeps the established VPN service bound when the activity closes. **About → Stop VPN** disconnects it. The app-private state directory holds the device identity and its saved networks.

The Rust agent owns one interface across the active networks. The Android service establishes the TUN and supplies its descriptor when addresses or exit routes change. Discovery and transport sockets use the selected physical network. TCP health checks bind to the VPN and the address of their own mesh network. The per-network transport selector offers `wg`, `awg`, `wg-quic` and `tcp-tls` in the same default order as the desktop. Each network retains its saved selection and priority. An advertised remote exit can carry the phone’s IPv4 internet traffic.

Applications using Android’s system resolver can connect to `<member>.<network>` and `<vip>.<network>`, for example `k8s.tsng:6443`. The VPN answers UDP and TCP DNS questions locally using the same signed roster and service records as the desktop. Unknown names in a joined mesh receive an authoritative negative answer. Other names go to Android’s resolver on the underlying Wi-Fi or cellular network, including while using a remote exit. Android 10 and later support arbitrary external DNS record types. On Android 8 and 9 the system lookup API supplies external A and AAAA records.

The tray and Android use the same egui network tiles, join form, device list, VIP editor and live traffic diagram from `crates/tsunagi-ui`. On Android, the Rust activity view opens each form in the current viewport. Kotlin handles the service, connectivity, rendering surface, input and clipboard.

Open **Exit node…** on a network tile to compare remote gateways by control RTT and data path. Tap a row and confirm to route IPv4 internet traffic through it. The selected exit has an ongoing notification, including when the peer is offline. **Disconnect exit node** restores the ordinary internet route and keeps mesh access and DNS active. Mesh-only mode has no persistent app notification. Android controls the system VPN indicator. Android 13 and later request notification permission for the exit notice. Starting with Android 14, an unlocked device allows an individual swipe to dismiss an ongoing VPN notification. [Android notification behavior](https://developer.android.com/about/versions/14/behavior-changes-all#non-dismissable-notifications)
