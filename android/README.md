# Android client

Download `tsunagi-android-<version>-arm64-v8a.apk` from the project's GitHub release and open it on an ARM64 phone running Android 8 or later. If prompted, allow the app that opened the file to install it. Later releases can update the installed app and preserve the mesh identity. A prototype signed with a local debug key requires a fresh install to switch to the release signer. Uninstalling the prototype removes its local identity and saved networks. [GitHub Releases](https://github.com/house-of-vanity/tsunagi/releases)

## Build from source

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

When Android chooses the first VPN address for a connection to another mesh, tsunagi translates TCP, UDP and ICMP echo traffic to that mesh’s address and returns replies to the original socket. Applications using other IPv4 protocols should bind to the address of their target mesh. If two sockets would use the same addresses, ports and protocol on the wire, the existing flow keeps its binding.

Applications using Android’s system resolver can connect to `<member>.<network>` and `<vip>.<network>`, for example `k8s.tsng:6443`. The VPN answers UDP and TCP DNS questions locally using the same signed roster and service records as the desktop. Unknown names in a joined mesh receive an authoritative negative answer. Other names go to Android’s resolver on the underlying Wi-Fi or cellular network, including while using a remote exit. Android 10 and later support arbitrary external DNS record types. On Android 8 and 9 the system lookup API supplies external A and AAAA records.

The tray and Android use the same egui network tiles, join form, device list, VIP editor and live traffic diagram from `crates/tsunagi-ui`. On Android, the Rust activity view opens each form in the current viewport. Kotlin handles the service, connectivity, rendering surface, input and clipboard.

Open **Exit node…** on a network tile to compare remote gateways by measured data RTT and data path. Tap a row and confirm to route IPv4 internet traffic through it. The selected exit has an ongoing notification, including when the peer is offline. **Disconnect exit node** restores the ordinary internet route and keeps mesh access and DNS active. Mesh-only mode has no persistent app notification. Android controls the system VPN indicator. Android 13 and later request notification permission for the exit notice. Starting with Android 14, an unlocked device allows an individual swipe to dismiss an ongoing VPN notification. [Android notification behavior](https://developer.android.com/about/versions/14/behavior-changes-all#non-dismissable-notifications)

## Check two networks on an emulator

Use a disposable ARM64 emulator. The test establishes a temporary VPN, sends UDP and system pings through the production TUN adapter to a local echo peer in each subnet, and checks that the originating applications receive their replies. Set `ANDROID_SERIAL` to that emulator's serial and run from the `android` directory.

```sh
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
adb -s "$ANDROID_SERIAL" install -r app/build/outputs/apk/debug/app-debug.apk
adb -s "$ANDROID_SERIAL" install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -s "$ANDROID_SERIAL" shell appops set cy.hexor.tsunagi ACTIVATE_VPN allow
adb -s "$ANDROID_SERIAL" shell am instrument -w cy.hexor.tsunagi.test/androidx.test.runner.AndroidJUnitRunner
```

## Configure GitHub release signing

The GitHub `Release` workflow builds and signs the ARM64 APK for each `v*` tag. The tag supplies the version name and the workflow run number supplies the Android version code. A rerun of the same workflow run keeps that code. The publish job attaches the verified APK alongside the desktop packages.

Before the first release, configure two repository Actions secrets. Use a dedicated single-key PKCS12 keystore with the same password for the keystore and key. Keep a private backup of the file and password so future releases can update existing installations. To create the first key, run this command once.

```sh
keytool -genkeypair -storetype PKCS12 -keystore "$HOME/tsunagi-release.p12" \
  -alias tsunagi -keyalg RSA -keysize 3072 -validity 10000
```

From this repository, upload the keystore. Enter its password when the second command prompts for it.

```sh
base64 < "$HOME/tsunagi-release.p12" | gh secret set ANDROID_KEYSTORE_BASE64
gh secret set ANDROID_KEYSTORE_PASSWORD
```

Missing signing credentials or a failed APK check stop publication. After correcting the secrets, rerun the failed release jobs for the same tag.
