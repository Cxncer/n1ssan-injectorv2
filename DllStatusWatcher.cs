using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace n1ssan_injector
{
    internal enum DllRuntimeState
    {
        Initializing,
        ChecksPassed,
        Ready,
        Degraded,
        Failed,
        Unknown,
    }

    internal sealed record DllStatusSnapshot(
        uint Pid,
        string BuildId,
        DllRuntimeState State,
        string Reason,
        DateTimeOffset TimestampUtc,
        TimeSpan Age);

    internal enum StatusOutcome
    {
        Ready,
        Degraded,
        Failed,
        TimedOut,
        ProcessExited,
    }

    /// <summary>
    /// Reads the versioned status record that n1ssan-dll.dll publishes:
    ///   N1SSAN_STATUS|1|&lt;UTC ISO-8601&gt;|&lt;pid&gt;|&lt;build-id&gt;|&lt;state&gt;|reason=&lt;reason&gt;
    /// A state is only trustworthy while its heartbeat is fresh (30 s), per the DLL status contract.
    /// </summary>
    internal static class DllStatusWatcher
    {
        internal const string Magic = "N1SSAN_STATUS";
        internal const string ProtocolVersion = "1";
        internal static readonly TimeSpan HeartbeatTimeout = TimeSpan.FromSeconds(30);

        internal static bool TryRead(uint pid, out DllStatusSnapshot? snapshot, out string message)
        {
            snapshot = null;
            string path = InjectorConfig.StatusFile(pid);

            if (!File.Exists(path))
            {
                message = "no status file yet";
                return false;
            }

            string line;

            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(stream);
                line = (reader.ReadLine() ?? string.Empty).Trim();
            }
            catch (IOException)
            {
                message = "status file is being written";
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                message = "status file is not readable";
                return false;
            }

            string[] fields = line.Split('|');

            if (fields.Length != 7 ||
                fields[0] != Magic ||
                fields[1] != ProtocolVersion ||
                !uint.TryParse(fields[3], NumberStyles.None, CultureInfo.InvariantCulture, out uint reportedPid) ||
                reportedPid != pid ||
                !DateTimeOffset.TryParse(fields[2], CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset timestamp) ||
                !fields[6].StartsWith("reason=", StringComparison.Ordinal))
            {
                message = "status record is malformed or belongs to another process";
                return false;
            }

            DllRuntimeState state = ParseState(fields[5]);
            string reason = fields[6]["reason=".Length..];
            TimeSpan age = DateTimeOffset.UtcNow - timestamp;

            if (age < TimeSpan.FromMinutes(-5))
            {
                message = "status timestamp is in the future";
                return false;
            }

            snapshot = new DllStatusSnapshot(pid, fields[4], state, reason, timestamp, age);
            message = "ok";
            return true;
        }

        private static DllRuntimeState ParseState(string value) => value.Trim() switch
        {
            "INITIALIZING" => DllRuntimeState.Initializing,
            "CHECKS_PASSED" => DllRuntimeState.ChecksPassed,
            "READY" => DllRuntimeState.Ready,
            "DEGRADED" => DllRuntimeState.Degraded,
            "FAILED" => DllRuntimeState.Failed,
            _ => DllRuntimeState.Unknown,
        };

        internal static async Task<StatusOutcome> WaitAsync(
            uint pid,
            TimeSpan timeout,
            Action<string> progress,
            CancellationToken ct)
        {
            var stopwatch = Stopwatch.StartNew();
            DllRuntimeState lastReported = DllRuntimeState.Unknown;
            string lastMessage = string.Empty;

            while (stopwatch.Elapsed < timeout)
            {
                ct.ThrowIfCancellationRequested();

                if (!GameProcess.IsAlive(pid))
                    return StatusOutcome.ProcessExited;

                if (TryRead(pid, out DllStatusSnapshot? snapshot, out string readMessage) && snapshot != null)
                {
                    bool fresh = snapshot.Age <= HeartbeatTimeout;

                    if (snapshot.State == DllRuntimeState.Failed)
                    {
                        progress($"DLL reported FAILED: {snapshot.Reason}");
                        return StatusOutcome.Failed;
                    }

                    if ((snapshot.State == DllRuntimeState.Ready || snapshot.State == DllRuntimeState.Degraded) && !fresh)
                    {
                        if (lastMessage != "stale")
                        {
                            progress($"DLL heartbeat is stale ({snapshot.Age.TotalSeconds:0}s old); waiting for a fresh one.");
                            lastMessage = "stale";
                        }
                    }
                    else
                    {
                        if (snapshot.State != lastReported)
                        {
                            string detail = snapshot.Reason.Length > 0 ? $" ({snapshot.Reason})" : string.Empty;
                            progress($"DLL state: {snapshot.State}{detail}");
                            lastReported = snapshot.State;
                        }

                        if (snapshot.State == DllRuntimeState.Ready && fresh)
                            return StatusOutcome.Ready;

                        if (snapshot.State == DllRuntimeState.Degraded && fresh)
                            return StatusOutcome.Degraded;
                    }
                }
                else if (readMessage != "no status file yet" && lastMessage != readMessage)
                {
                    progress(readMessage);
                    lastMessage = readMessage;
                }

                await Task.Delay(1000, ct).ConfigureAwait(false);
            }

            return StatusOutcome.TimedOut;
        }
    }
}
