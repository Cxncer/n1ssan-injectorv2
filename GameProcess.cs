using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace n1ssan_injector
{
    /// <summary>
    /// Read-only helpers for finding CS2 and waiting until it has finished loading.
    /// Nothing here writes to the game process.
    /// </summary>
    internal static class GameProcess
    {
        internal const string GameExeName = "cs2.exe";
        internal const string ClientModuleName = "client.dll";

        /// <summary>Time CS2 needs after client.dll is mapped before the game is usable.</summary>
        internal static readonly TimeSpan SettleDelay = TimeSpan.FromSeconds(3);

        internal static uint FindProcessId(string exeName)
        {
            IReadOnlyList<uint> ids = FindProcessIds(exeName);
            return ids.Count == 0 ? 0 : SelectPreferred(ids);
        }

        internal static IReadOnlyList<uint> FindProcessIds(string exeName)
        {
            IntPtr snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPPROCESS, 0);
            if (snapshot == InvalidHandle)
                return Array.Empty<uint>();

            var ids = new List<uint>();

            try
            {
                var entry = new NativeMethods.PROCESSENTRY32W { dwSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.PROCESSENTRY32W>() };

                for (bool ok = NativeMethods.Process32FirstW(snapshot, ref entry); ok; ok = NativeMethods.Process32NextW(snapshot, ref entry))
                {
                    if (string.Equals(entry.szExeFile, exeName, StringComparison.OrdinalIgnoreCase))
                        ids.Add(entry.th32ProcessID);
                }
            }
            finally
            {
                NativeMethods.CloseHandle(snapshot);
            }

            return ids;
        }

        /// <summary>
        /// Prefers a process that already has client.dll (the real game) and otherwise the most recently
        /// started one, so a lingering cs2.exe from an earlier session is not picked over a fresh launch.
        /// </summary>
        internal static uint SelectPreferred(IReadOnlyList<uint> pids)
        {
            if (pids.Count == 1)
                return pids[0];

            foreach (uint pid in pids)
            {
                if (HasModule(pid, ClientModuleName))
                    return pid;
            }

            uint newest = pids[0];
            DateTime newestStart = DateTime.MinValue;

            foreach (uint pid in pids)
            {
                try
                {
                    using var process = System.Diagnostics.Process.GetProcessById((int)pid);
                    DateTime start = process.StartTime;

                    if (start > newestStart)
                    {
                        newestStart = start;
                        newest = pid;
                    }
                }
                catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    // Process exited between the snapshot and the query; keep the current choice.
                }
            }

            return newest;
        }

        /// <summary>True while the process still exists. Safe for processes we cannot open.</summary>
        internal static bool IsAlive(uint pid)
        {
            if (pid == 0)
                return false;

            IntPtr handle = NativeMethods.OpenProcess(NativeMethods.SYNCHRONIZE, false, pid);
            if (handle == IntPtr.Zero)
                return false;

            try
            {
                return NativeMethods.WaitForSingleObject(handle, 0) == NativeMethods.WAIT_TIMEOUT;
            }
            finally
            {
                NativeMethods.CloseHandle(handle);
            }
        }

        internal static string? TryGetExecutablePath(uint pid)
        {
            IntPtr handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_INFORMATION, false, pid);
            if (handle == IntPtr.Zero)
                return null;

            try
            {
                var buffer = new System.Text.StringBuilder(1024);
                uint size = (uint)buffer.Capacity;
                if (!QueryFullProcessImageNameW(handle, 0, buffer, ref size))
                    return null;
                return buffer.ToString();
            }
            finally
            {
                NativeMethods.CloseHandle(handle);
            }
        }

        /// <summary>
        /// Lists module names in the target process. Snapshots can fail transiently with
        /// ERROR_BAD_LENGTH while the target is loading modules, so retry a few times.
        /// </summary>
        internal static IReadOnlyList<string> ListModules(uint pid)
        {
            IntPtr snapshot = InvalidHandle;

            for (int attempt = 0; attempt < 5; attempt++)
            {
                snapshot = NativeMethods.CreateToolhelp32Snapshot(
                    NativeMethods.TH32CS_SNAPMODULE | NativeMethods.TH32CS_SNAPMODULE32, pid);

                if (snapshot != InvalidHandle)
                    break;

                Thread.Sleep(50);
            }

            if (snapshot == InvalidHandle)
                return Array.Empty<string>();

            var modules = new List<string>();

            try
            {
                var entry = new NativeMethods.MODULEENTRY32W { dwSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.MODULEENTRY32W>() };

                for (bool ok = NativeMethods.Module32FirstW(snapshot, ref entry); ok; ok = NativeMethods.Module32NextW(snapshot, ref entry))
                    modules.Add(entry.szModule);
            }
            finally
            {
                NativeMethods.CloseHandle(snapshot);
            }

            return modules;
        }

        internal static bool HasModule(uint pid, string moduleName)
            => ListModules(pid).Any(name => string.Equals(name, moduleName, StringComparison.OrdinalIgnoreCase));

        /// <summary>Matches any module whose file name starts with the prefix, regardless of extension.</summary>
        internal static bool HasModulePrefix(uint pid, string prefix)
            => ListModules(pid).Any(name => name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

        /// <summary>Waits for cs2.exe to appear. Returns 0 if the timeout expires.</summary>
        internal static async Task<uint> WaitForGameAsync(TimeSpan timeout, CancellationToken ct, Action<string>? progress = null)
        {
            uint pid = FindProcessId(GameExeName);
            if (pid != 0)
                return pid;

            var stopwatch = Stopwatch.StartNew();
            var nextNotice = TimeSpan.Zero;

            while (stopwatch.Elapsed < timeout)
            {
                ct.ThrowIfCancellationRequested();
                await Task.Delay(500, ct).ConfigureAwait(false);

                pid = FindProcessId(GameExeName);
                if (pid != 0)
                    return pid;

                if (progress != null && stopwatch.Elapsed >= nextNotice)
                {
                    progress($"Waiting for {GameExeName}... ({stopwatch.Elapsed.TotalSeconds:0}s)");
                    nextNotice = stopwatch.Elapsed + TimeSpan.FromSeconds(10);
                }
            }

            return 0;
        }

        /// <summary>Waits until client.dll is mapped, or the process exits. Returns false on timeout/exit.</summary>
        internal static async Task<bool> WaitForClientModuleAsync(uint pid, TimeSpan timeout, CancellationToken ct, Action<string>? progress = null)
        {
            var stopwatch = Stopwatch.StartNew();
            var nextNotice = TimeSpan.Zero;

            while (stopwatch.Elapsed < timeout)
            {
                ct.ThrowIfCancellationRequested();

                if (!IsAlive(pid))
                    return false;

                if (HasModule(pid, ClientModuleName))
                    return true;

                if (progress != null && stopwatch.Elapsed >= nextNotice)
                {
                    progress($"Waiting for {ClientModuleName} to load... ({stopwatch.Elapsed.TotalSeconds:0}s)");
                    nextNotice = stopwatch.Elapsed + TimeSpan.FromSeconds(10);
                }

                await Task.Delay(500, ct).ConfigureAwait(false);
            }

            return false;
        }

        /// <summary>Gives the game a moment to finish initialising after client.dll appears.</summary>
        internal static async Task SettleAsync(CancellationToken ct)
            => await Task.Delay(SettleDelay, ct).ConfigureAwait(false);

        /// <summary>Wait for the injected module to show up in the target's module list.</summary>
        internal static async Task<bool> WaitForModuleAsync(uint pid, string dllFileName, string prefix, TimeSpan timeout, CancellationToken ct)
        {
            var stopwatch = Stopwatch.StartNew();
            while (stopwatch.Elapsed < timeout)
            {
                if (!IsAlive(pid))
                    return false;

                if (HasModule(pid, dllFileName) || HasModulePrefix(pid, prefix))
                    return true;

                await Task.Delay(250, ct).ConfigureAwait(false);
            }

            return false;
        }

        internal static bool IsTarget64Bit(uint pid, out string? error)
        {
            error = null;

            IntPtr handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_INFORMATION, false, pid);
            if (handle == IntPtr.Zero)
            {
                // We will find out during injection. Do not fail the pre-flight on a handle we could not open.
                return true;
            }

            try
            {
                if (NativeMethods.IsWow64Process(handle, out bool wow64) && wow64)
                {
                    error = $"{GameExeName} (PID {pid}) is a 32-bit process; n1ssan-dll.dll is 64-bit and cannot load into it.";
                    return false;
                }

                return true;
            }
            finally
            {
                NativeMethods.CloseHandle(handle);
            }
        }

        internal static bool IsElevated()
        {
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), NativeMethods.TOKEN_QUERY, out IntPtr token))
                return false;

            try
            {
                return NativeMethods.GetTokenInformation(
                           token, NativeMethods.TokenElevation,
                           out NativeMethods.TOKEN_ELEVATION elevation,
                           (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.TOKEN_ELEVATION>(),
                           out _)
                       && elevation.TokenIsElevated != 0;
            }
            finally
            {
                NativeMethods.CloseHandle(token);
            }
        }

        private static readonly IntPtr InvalidHandle = new(-1);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, System.Text.StringBuilder lpExeName, ref uint lpdwSize);
    }
}
