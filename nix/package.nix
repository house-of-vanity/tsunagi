{
  withTray ? true,
  lib,
  rustPlatform,
  pkg-config,
  copyDesktopItems,
  wrapGAppsHook3,
  gtk3,
  libayatana-appindicator,
  libglvnd,
  libxkbcommon,
  vulkan-loader,
  wayland,
  xdotool,
  libx11,
  libxcursor,
  libxi,
  libxrandr,
}:

let
  # The tray is an egui app that loads graphics, windowing and appindicator
  # libraries at run time, so they have to be put on its library path by hand.
  trayRuntimeLibs = [
    libayatana-appindicator
    libglvnd
    libxkbcommon
    vulkan-loader
    wayland
    libx11
    libxcursor
    libxi
    libxrandr
  ];
in
rustPlatform.buildRustPackage {
  pname = if withTray then "tsunagi" else "tsunagi-cli";
  version = "0.1.0";

  src = lib.cleanSource ../.;
  cargoLock.lockFile = ../Cargo.lock;

  cargoBuildFlags = [
    "--bin"
    "tsng"
  ]
  ++ lib.optionals withTray [
    "--bin"
    "tsunagi-tray"
  ];

  # The suite opens real sockets and interfaces; it runs in CI instead.
  doCheck = false;

  nativeBuildInputs = [ pkg-config ] ++ lib.optionals withTray [
    copyDesktopItems
    wrapGAppsHook3
  ];
  buildInputs = lib.optionals withTray [
    gtk3
    libayatana-appindicator
    xdotool
  ];

  dontWrapGApps = true;

  postInstall = ''
    install -Dm644 dist/linux/50-tsunagi-resolved.rules \
      "$out/share/doc/tsunagi/50-tsunagi-resolved.rules"
  ''
  + lib.optionalString withTray ''
    install -Dm644 dist/linux/tsunagi.svg \
      "$out/share/icons/hicolor/scalable/apps/tsunagi.svg"
    install -Dm644 dist/linux/tsunagi-tray.desktop \
      "$out/share/applications/tsunagi-tray.desktop"
  '';

  postFixup = lib.optionalString withTray ''
    wrapProgram "$out/bin/tsunagi-tray" \
      "''${gappsWrapperArgs[@]}" \
      --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath trayRuntimeLibs}:/run/opengl-driver/lib
  '';

  meta = {
    description = "Serverless mesh VPN: join a network with a name and a secret";
    homepage = "https://github.com/house-of-vanity/tsunagi";
    license = lib.licenses.wtfpl;
    mainProgram = "tsng";
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
