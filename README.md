# n1ssan-injector

Loads `n1ssan-dll.dll` into `cs2.exe` once the game has finished loading.

This is the standalone loader for the n1ssan toolchain. It only injects; it never edits game files,
never touches Steam, and never unloads the DLL (the DLL owns hooks and a worker thread, so unloading
it mid-session would crash CS2).

## Requirements

- Windows 10/11 x64
- .NET 8 runtime (the launcher already needs it)
- `n1ssan-dll.dll` built for **x64 Release**, with `MinHook.x64.dll` in the same folder
- CS2 started with `-allow_third_party_software` (see [Trusted Mode](#trusted-mode))

## Quick start

```powershell
# from development/n1ssan-injector
dotnet build -c Release
.\bin\Release\net8.0-windows\n1ssan-injector.exe
```

With no arguments it finds `n1ssan-dll.dll`, waits up to 5 minutes for `cs2.exe`, waits for
`client.dll` to load, gives the game 3 more seconds, injects, confirms the module is listed, and
then waits for the DLL's `READY` heartbeat.

```text
n1ssan injector 2.0.0
DLL:     E:\...\CS2-n1ssan\x64\Release\n1ssan-dll.dll
Source:  CS2-n1ssan build output
Imports: 11 DLLs / 160 functions resolved.
MinHook: MinHook.x64.dll
Target:  cs2.exe (PID 12345)
Waiting for client.dll (up to 120s)...
Game loaded; letting it settle.
Injecting n1ssan-dll.dll...
LoadLibraryW returned success; confirming the module is listed.
Module is loaded.
Waiting for the DLL to report READY (up to 120s)...
DLL state: INITIALIZING (worker_started)
DLL state: READY (runtime_worker_heartbeat)
DLL is READY.

n1ssan is loaded in CS2.
Log:     E:\...\CS2-n1ssan\x64\Release\n1ssalogs.md
Status:  C:\Users\you\AppData\Local\n1ssan\status\cs2-12345.status
RESULT=OK pid=12345 status=injected dll="E:\...\n1ssan-dll.dll"
```

## Options

| Option | Meaning |
| --- | --- |
| `--dll <path>` | Inject this DLL instead of searching for `n1ssan-dll.dll` |
| `--pid <pid>` | Target an existing process (used by the launcher, or for testing) |
| `--wait <seconds>` | How long to wait for CS2 to start (default `300`; `0` = fail immediately) |
| `--no-wait` | Same as `--wait 0` |
| `--inject-timeout <sec>` | How long `LoadLibraryW` may take inside CS2 (default `60`) |
| `--status-timeout <sec>` | How long to wait for the DLL's `READY` heartbeat (default `120`) |
| `--no-status` | Skip the status handshake |
| `--no-deps` | Skip the imported-DLL/function pre-check |
| `--skip-client-wait` | Do not wait for `client.dll` (testing only) |
| `--elevate` | Relaunch through UAC when the injector is not elevated |
| `--quiet` | Print only errors and the final `RESULT=` line |
| `-h`, `--help` | Usage |
| `--version` | Version |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Injected, or the DLL was already loaded |
| `2` | Bad arguments |
| `3` | DLL problem: missing, not x64, unmet dependency, MinHook missing, unreadable |
| `4` | CS2 not found, or it closed before injection |
| `5` | Injection failed (access denied, allocation/write/thread failure, LoadLibrary error) |
| `6` | CS2 loaded the DLL and unloaded it immediately (Trusted Mode) |
| `7` | The DLL reported `FAILED` during startup |
| `8` | Injected, but no fresh `READY` heartbeat within the timeout |
| `130` | Cancelled with Ctrl+C |

The final line is machine-readable, for launcher integration:

```text
RESULT=OK pid=<pid> status=injected|already-loaded dll="<path>"
RESULT=FAIL code=<exit code>
```

## How it decides when to inject

The DLL pattern-scans `client.dll` on startup, so injecting before `client.dll` is mapped fails or
wastes the DLL's 30-second wait. The injector therefore:

1. finds `cs2.exe` (preferring a process that already has `client.dll`, otherwise the newest one);
2. waits until `client.dll` appears in the target's module list (120 s);
3. waits 3 s for the game to finish initialising;
4. injects and confirms the module is listed;
5. waits for the DLL status record to become `READY` or `DEGRADED`.

If the DLL is already loaded, the injector exits `0` with `status=already-loaded`.

## DLL discovery

1. `--dll <path>`
2. `N1SSAN_DLL_PATH`
3. `n1ssan-dll.dll` next to the injector
4. walking up from the injector (or the current directory), matching:
   `n1ssan-dll.dll`, `x64\Release\n1ssan-dll.dll`, `CS2-n1ssan\x64\Release\n1ssan-dll.dll`,
   `CS2-n1ssan\x64\Debug\n1ssan-dll.dll`, `n1ssan-dll\x64\Release\n1ssan-dll.dll`

Before injecting it verifies the file is a 64-bit PE DLL, that every imported DLL and function exists
on this PC, and that `MinHook.x64.dll` sits beside it. A Debug build of the DLL needs the Visual
Studio debug runtime (`VCRUNTIME140D`, `MSVCP140D`); ship the x64 Release build.

## Trusted Mode

CS2 unloads third-party modules unless the game was launched with:

```text
-allow_third_party_software
```

In Steam: **right-click Counter-Strike 2 → Properties → Launch Options**, add the switch, restart CS2.
It is Valve's own switch, and Valve warns that it can lower your Trust Factor. The injector detects the
"loaded then unloaded immediately" case (exit `6`) and prints this same guidance.

## The status handshake

The DLL publishes `%LOCALAPPDATA%\n1ssan\status\cs2-<pid>.status`:

```text
N1SSAN_STATUS|1|<UTC timestamp>|<pid>|<build id>|<state>|reason=<reason>
```

States: `INITIALIZING`, `CHECKS_PASSED`, `READY`, `DEGRADED`, `FAILED`. A `READY`/`DEGRADED` record
only counts while its heartbeat is at most 30 seconds old. `DEGRADED` is treated as success (the
optional glove-schema feature is unavailable). `FAILED` prints the reason and exits `7`.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `RESULT=FAIL code=5`, "Access denied" | CS2 runs elevated (or another protected process). Run the injector as administrator, or use `--elevate`. |
| Exit `6` | Trusted Mode. Add `-allow_third_party_software` and restart CS2. |
| Exit `3`, "MinHook is missing" | Copy `MinHook.x64.dll` next to `n1ssan-dll.dll`. |
| Exit `3`, missing dependency | Install the [Visual C++ 2015–2022 x64 Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe), or rebuild the DLL as x64 Release. |
| Exit `3`, "DLL is only N bytes" / "can't be read" | An antivirus quarantined the DLL. Add an exclusion for the DLL folder and rebuild/copy it again. |
| Exit `5`, `ERROR_MOD_NOT_FOUND` | A dependency of the DLL is missing in this PC's context (usually the VC runtime). |
| Exit `5`, `ERROR_ACCESS_DENIED` / `ERROR_VIRUS_*` | Antivirus or a security policy blocked the DLL. Check Windows Security exclusions. |
| Exit `7`, reason `loadout_empty` | The DLL found no loadout: it reads `n1ssan-data.json` from the `n1ssan-web-bridge` folder (or `N1SSAN_DATA_FILE`). Fill in a loadout in the web UI first. |
| Exit `7`, reason `loadout_compatibility_failed` | A selected paint kit is not compatible with the item; see the preflight lines in `n1ssalogs.md`. |
| Exit `8` | The DLL is running but never reached `READY`. Read `n1ssalogs.md`; scanning the live schema can take a while. |

Logs always live next to the DLL as `n1ssalogs.md`.

## Building and publishing

```powershell
dotnet build -c Release

# optional: single-file build for distribution
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
```

The project is `net8.0-windows`, `x64`, with `asInvoker` in `app.manifest` so the launcher can start
it without a UAC prompt. Use `--elevate` only when CS2 itself is elevated.

## Design notes

- The remote thread runs a small x64 stub (`LoadLibraryW` + `GetLastError`) instead of `LoadLibraryW`
  directly, so a failure reports the real Windows error code, not just a `NULL` exit code.
- The DLL path is written as UTF-16, so non-English install paths work.
- `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` use the exact SDK access rights
  (`PROCESS_VM_OPERATION`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_QUERY_INFORMATION`,
  `PROCESS_CREATE_THREAD`).
- If the remote thread is still loading after `--inject-timeout`, the remote block is intentionally
  **not** freed (the thread may still be executing it) and the injector explains how to recover.
- There is no unload path on purpose: `n1ssan-dll.dll` installs hooks and runs a heartbeat thread that
  has no shutdown, so `FreeLibrary` would crash the game.
