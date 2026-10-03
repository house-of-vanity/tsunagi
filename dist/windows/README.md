# Running tsunagi on Windows

## The installer (recommended)

`tsunagi-setup-<version>-x86_64.exe` does everything in one go. Run it as an
administrator (it asks):

- installs `tsng.exe`, the tray app and **Wintun** to `C:\Program Files\Tsunagi`;
- registers and starts the **Tsunagi** Windows service (it starts at boot and
  restarts after a crash), running as the system account;
- adds `tsng` to the PATH and an inbound Windows Firewall rule for the agent
  (both are tasks you can untick);
- starts the tray icon at sign-in.

Where things live: the device's identity and networks in
`%ProgramData%\Tsunagi\data` (readable only by administrators and the system),
the log in `%ProgramData%\Tsunagi\logs\tsng.log`. The service keeps its own
state: networks joined by an agent you started by hand (`tsng up`, which keeps
its data in your user profile) are not carried over; join them again with
`tsng join`. The installer stops such an agent, because it cannot run beside the
service.

`tsng status`, `tsng join` and the tray work from an ordinary, non-elevated
terminal. Manage the service with the Services app or `sc stop Tsunagi` /
`sc start Tsunagi`. Silent install: `/VERYSILENT /SUPPRESSMSGBOXES`; choose
tasks with `/TASKS="!autostart,addtopath,firewall"`. Uninstalling removes the
service, the firewall rule and the PATH entry, and asks before deleting the
data.

## By hand (the zip)

This archive holds `tsng.exe`. The overlay interface is a Wintun adapter, so
the agent needs two things to carry real traffic:

1. **`wintun.dll` beside the executable.** Download it from
   <https://www.wintun.net>, take the DLL for your architecture (`amd64`), and
   put it in the same folder as `tsng.exe`.
2. **An elevated process.** Creating the adapter requires Administrator rights.

Open PowerShell or Command Prompt with **Run as administrator** and start the
agent there:

```powershell
.\tsng.exe up
```

Run the commands that control it (`join`, `status`, `dns`, `network`) as the
same user with the same elevation. The agent serves its control interface on a
named pipe under `%ProgramData%\tsunagi`, so an elevated client finds it
regardless of which account started the agent.

## Without touching the OS

```powershell
.\tsng.exe up --no-tun
```

Tunnels form and handshake between agents, but no adapter, address or route is
created, so traffic never reaches the operating system. Needs no Wintun and no
elevation.

## What the agent installs

Everything is tagged to its own adapter, computed from local state, and
reversible — removed when a network leaves, broadcast is turned off, or the
agent stops:

- a Wintun adapter configured with `netsh` (addresses, MTU);
- while broadcast is on, a `255.255.255.255` route through the adapter and an
  inbound-UDP firewall allowance from the overlay range;
- the Name Resolution Policy Table entry that sends the overlay zones' questions
  to the local resolver.

Nothing taken from a remote peer ever becomes a path, a command argument or an
OS setting.
