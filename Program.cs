using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace n1ssan_injector
{
    internal static class ExitCodes
    {
        internal const int Success = 0;
        internal const int Unexpected = 1;
        internal const int Usage = 2;
        internal const int DllProblem = 3;
        internal const int GameNotFound = 4;
        internal const int InjectionFailed = 5;
        internal const int ModuleRejected = 6;
        internal const int DllFailed = 7;
        internal const int StatusTimeout = 8;
        internal const int Cancelled = 130;
    }

    internal static class Program
    {
        private const string Version = "2.0.0";
        private const string DllModulePrefix = "n1ssan";

        private static readonly TimeSpan ClientModuleTimeout = TimeSpan.FromSeconds(120);
        private static readonly TimeSpan ModuleVerifyTimeout = TimeSpan.FromSeconds(10);

        private static bool s_quiet;

        private static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.Title = "n1ssan injector";

            Options options;

            try
            {
                options = Options.Parse(args);
            }
            catch (ArgumentException ex)
            {
                Console.Error.WriteLine($"ERROR: {ex.Message}");
                Console.Error.WriteLine();
                PrintUsage();
                return ExitCodes.Usage;
            }

            if (options.ShowHelp)
            {
                PrintUsage();
                return ExitCodes.Success;
            }

            if (options.ShowVersion)
            {
                Console.WriteLine(Version);
                return ExitCodes.Success;
            }

            s_quiet = options.Quiet;

            if (options.Elevate && !GameProcess.IsElevated())
                return RelaunchElevated(args);

            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cancellation.Cancel();
            };

            try
            {
                return await RunAsync(options, cancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                Console.Error.WriteLine("Cancelled.");
                return ExitCodes.Cancelled;
            }
            catch (Exception ex)
            {
                return Fail(ExitCodes.Unexpected, $"Unexpected error: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private static async Task<int> RunAsync(Options options, CancellationToken ct)
        {
            Emit($"n1ssan injector {Version}");

            if (GameProcess.IsElevated())
                Emit("Running elevated.");

            // ---- Payload DLL ----
            ResolvedDll resolved;

            try
            {
                resolved = InjectorConfig.ResolveDllPath(options.DllPath);
            }
            catch (Exception ex) when (ex is FileNotFoundException or IOException or UnauthorizedAccessException)
            {
                return Fail(ExitCodes.DllProblem, ex.Message);
            }

            Emit($"DLL:     {resolved.Path}");
            Emit($"Source:  {resolved.Source}");

            string dllDirectory = Path.GetDirectoryName(resolved.Path) ?? Directory.GetCurrentDirectory();
            string dllFileName = Path.GetFileName(resolved.Path);

            DllInspector.Result inspection = DllInspector.Inspect(resolved.Path, checkDependencies: !options.SkipDependencyCheck);

            if (inspection.Problems.Count > 0)
            {
                foreach (string problem in inspection.Problems)
                    Console.Error.WriteLine($"ERROR: {problem}");

                if (!inspection.IsValid)
                {
                    if (inspection.LooksQuarantined)
                    {
                        Console.Error.WriteLine();
                        Console.Error.WriteLine(DllInjector.AntivirusHint(dllDirectory));
                    }

                    return Fail(ExitCodes.DllProblem, "The DLL cannot be injected.");
                }
            }

            if (inspection.MissingDependencies.Count > 0)
            {
                Console.Error.WriteLine("ERROR: This PC is missing things the DLL needs:");

                foreach (string dependency in inspection.MissingDependencies)
                    Console.Error.WriteLine($"         {dependency}");

                Console.Error.WriteLine();
                Console.Error.WriteLine("Names ending in 'D' (VCRUNTIME140D, MSVCP140D, ucrtbased) come from a Debug build:");
                Console.Error.WriteLine("rebuild CS2-n1ssan as x64 Release, or install the Visual C++ 2015-2022 x64 Redistributable");
                Console.Error.WriteLine("for the release runtime.");
                return Fail(ExitCodes.DllProblem, "The DLL has unmet dependencies.");
            }

            if (!options.SkipDependencyCheck)
                Emit($"Imports: {inspection.ImportedDllCount} DLLs / {inspection.ImportedFunctionCount} functions resolved.");

            string minHook = InjectorConfig.VerifyMinHook(dllDirectory, out List<string> minHookProblems);

            if (minHookProblems.Count > 0)
            {
                foreach (string problem in minHookProblems)
                    Console.Error.WriteLine($"ERROR: {problem}");

                return Fail(ExitCodes.DllProblem, "MinHook is not usable.");
            }

            Emit($"MinHook: {Path.GetFileName(minHook)}");

            // ---- Target process ----
            uint pid = await SelectGameProcessAsync(options, ct).ConfigureAwait(false);

            if (pid == 0)
                return Fail(ExitCodes.GameNotFound,
                    options.WaitForGame > TimeSpan.Zero
                        ? $"cs2.exe did not start within {options.WaitForGame.TotalSeconds:0} seconds."
                        : "cs2.exe is not running. Start Counter-Strike 2 first, or run the injector without --wait 0.");

            string targetName = DescribeTarget(pid);
            bool isCs2Target = string.Equals(targetName, GameProcess.GameExeName, StringComparison.OrdinalIgnoreCase);

            Emit($"Target:  {targetName} (PID {pid})");

            if (!GameProcess.IsTarget64Bit(pid, out string? architectureError))
                return Fail(ExitCodes.GameNotFound, architectureError ?? "The target process is not 64-bit.");

            if (GameProcess.HasModule(pid, dllFileName) || GameProcess.HasModulePrefix(pid, DllModulePrefix))
            {
                Emit($"{dllFileName} is already loaded in {targetName}. Nothing to inject.");

                if (DllStatusWatcher.TryRead(pid, out DllStatusSnapshot? existing, out _) && existing != null)
                    Emit($"DLL state: {existing.State} ({existing.Age.TotalSeconds:0}s old)");

                Console.WriteLine($"RESULT=OK pid={pid} status=already-loaded");
                return ExitCodes.Success;
            }

            // ---- Wait until the game has finished loading ----
            if (options.SkipClientWait)
            {
                Emit("Skipping the client.dll wait (--skip-client-wait).");
            }
            else if (!isCs2Target)
            {
                Emit($"{targetName} is not cs2.exe; skipping the client.dll wait.");
            }
            else
            {
                Emit($"Waiting for {GameProcess.ClientModuleName} (up to {ClientModuleTimeout.TotalSeconds:0}s)...");

                bool clientLoaded = await GameProcess
                    .WaitForClientModuleAsync(pid, ClientModuleTimeout, ct, Emit)
                    .ConfigureAwait(false);

                if (!clientLoaded)
                {
                    return Fail(ExitCodes.GameNotFound,
                        GameProcess.IsAlive(pid)
                            ? $"{GameProcess.ClientModuleName} did not load within {ClientModuleTimeout.TotalSeconds:0} seconds. " +
                              "The game is still starting or the wrong process was targeted."
                            : $"{targetName} exited before it finished loading.");
                }

                Emit("Game loaded; letting it settle.");
                await GameProcess.SettleAsync(ct).ConfigureAwait(false);
            }

            if (!GameProcess.IsAlive(pid))
                return Fail(ExitCodes.GameNotFound, $"{targetName} exited before injection.");

            // ---- Inject ----
            Emit($"Injecting {dllFileName}...");

            var injector = new DllInjector(resolved.Path);
            InjectOutcome outcome = await injector
                .InjectAsync(pid, options.InjectTimeout, ct)
                .ConfigureAwait(false);

            if (!outcome.Ok)
            {
                Console.Error.WriteLine($"ERROR: {outcome.Message}");

                if (outcome.Status == InjectStatus.AccessDenied && !GameProcess.IsElevated())
                    Console.Error.WriteLine("       Run this injector as administrator.");

                if (outcome.Status == InjectStatus.LoadFailed && outcome.Win32Error is
                    NativeMethods.ERROR_FILE_NOT_FOUND or NativeMethods.ERROR_ACCESS_DENIED or
                    NativeMethods.ERROR_VIRUS_INFECTED or NativeMethods.ERROR_VIRUS_DELETED)
                {
                    Console.Error.WriteLine();
                    Console.Error.WriteLine(DllInjector.AntivirusHint(dllDirectory));
                }

                int code = outcome.Status == InjectStatus.ProcessNotFound
                    ? ExitCodes.GameNotFound
                    : ExitCodes.InjectionFailed;

                return Fail(code, "Injection failed.");
            }

            Emit("LoadLibraryW returned success; confirming the module is listed.");

            bool modulePresent = await GameProcess
                .WaitForModuleAsync(pid, dllFileName, DllModulePrefix, ModuleVerifyTimeout, ct)
                .ConfigureAwait(false);

            if (!modulePresent)
            {
                if (isCs2Target)
                    PrintTrustedModeHelp();
                else
                    Console.Error.WriteLine($"The target removed {dllFileName} immediately after loading it.");

                return Fail(ExitCodes.ModuleRejected,
                    $"{targetName} unloaded the DLL immediately after loading it.");
            }

            Emit("Module is loaded.");

            // ---- Status handshake ----
            if (options.SkipStatus)
            {
                Emit("Skipping the DLL status wait (--no-status).");
            }
            else if (!isCs2Target)
            {
                Emit($"{targetName} is not cs2.exe; skipping the DLL status wait.");
            }
            else
            {
                Emit($"Waiting for the DLL to report READY (up to {options.StatusTimeout.TotalSeconds:0}s)...");

                StatusOutcome status = await DllStatusWatcher
                    .WaitAsync(pid, options.StatusTimeout, Emit, ct)
                    .ConfigureAwait(false);

                switch (status)
                {
                    case StatusOutcome.Ready:
                        Emit("DLL is READY.");
                        break;

                    case StatusOutcome.Degraded:
                        Emit("DLL is DEGRADED (an optional glove-schema feature is unavailable); it will still run.");
                        break;

                    case StatusOutcome.Failed:
                        Console.Error.WriteLine("ERROR: The DLL failed during startup.");
                        Console.Error.WriteLine($"       Status: {InjectorConfig.StatusFile(pid)}");
                        Console.Error.WriteLine($"       Log:    {Path.Combine(dllDirectory, "n1ssalogs.md")}");
                        return Fail(ExitCodes.DllFailed, "The DLL reported FAILED.");

                    case StatusOutcome.ProcessExited:
                        return Fail(ExitCodes.GameNotFound, "cs2.exe exited while the DLL was initialising.");

                    case StatusOutcome.TimedOut:
                        Console.Error.WriteLine($"ERROR: No READY heartbeat within {options.StatusTimeout.TotalSeconds:0} seconds.");
                        Console.Error.WriteLine($"       Status: {InjectorConfig.StatusFile(pid)}");
                        Console.Error.WriteLine($"       Log:    {Path.Combine(dllDirectory, "n1ssalogs.md")}");
                        return Fail(ExitCodes.StatusTimeout, "The DLL did not report READY in time.");
                }
            }

            Console.WriteLine();

            if (isCs2Target && string.Equals(dllFileName, InjectorConfig.DllName, StringComparison.OrdinalIgnoreCase))
            {
                Emit("n1ssan is loaded in CS2.");
                Emit($"Log:     {Path.Combine(dllDirectory, "n1ssalogs.md")}");
                Emit($"Status:  {InjectorConfig.StatusFile(pid)}");
            }
            else
            {
                Emit($"{dllFileName} is loaded into {targetName} (PID {pid}).");
            }

            Console.WriteLine($"RESULT=OK pid={pid} status=injected dll=\"{resolved.Path}\"");

            return ExitCodes.Success;
        }

        private static async Task<uint> SelectGameProcessAsync(Options options, CancellationToken ct)
        {
            if (options.Pid is uint explicitPid)
            {
                if (!GameProcess.IsAlive(explicitPid))
                {
                    Console.Error.WriteLine($"ERROR: No running process has PID {explicitPid}.");
                    return 0;
                }

                string? exePath = GameProcess.TryGetExecutablePath(explicitPid);

                if (exePath != null &&
                    !string.Equals(Path.GetFileName(exePath), GameProcess.GameExeName, StringComparison.OrdinalIgnoreCase))
                {
                    Console.Error.WriteLine($"WARNING: PID {explicitPid} is {Path.GetFileName(exePath)}, not {GameProcess.GameExeName}.");
                }

                return explicitPid;
            }

            if (options.WaitForGame <= TimeSpan.Zero)
                return GameProcess.FindProcessId(GameProcess.GameExeName);

            return await GameProcess
                .WaitForGameAsync(options.WaitForGame, ct, Emit)
                .ConfigureAwait(false);
        }

        private static string DescribeTarget(uint pid)
        {
            string? path = GameProcess.TryGetExecutablePath(pid);
            return path == null ? GameProcess.GameExeName : Path.GetFileName(path);
        }

        private static void PrintTrustedModeHelp()
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine("CS2 removed the DLL right after loading it. That is CS2 Trusted Mode, which unloads");
            Console.Error.WriteLine("third-party modules unless the game was started with:");
            Console.Error.WriteLine();
            Console.Error.WriteLine("    -allow_third_party_software");
            Console.Error.WriteLine();
            Console.Error.WriteLine("In Steam: right-click Counter-Strike 2 -> Properties -> Launch Options, add that switch,");
            Console.Error.WriteLine("then restart the game. (It is Valve's own switch; using it can lower your Trust Factor.)");
        }

        private static int RelaunchElevated(string[] args)
        {
            string? executable = Environment.ProcessPath;

            if (string.IsNullOrEmpty(executable))
                return Fail(ExitCodes.InjectionFailed, "Could not determine the injector path to relaunch elevated.");

            var startInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Directory.GetCurrentDirectory(),
            };

            foreach (string argument in args)
                startInfo.ArgumentList.Add(argument);

            try
            {
                using Process? elevated = Process.Start(startInfo);

                if (elevated == null)
                    return Fail(ExitCodes.InjectionFailed, "Elevation was cancelled.");

                elevated.WaitForExit();
                return elevated.ExitCode;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return Fail(ExitCodes.InjectionFailed, "Elevation was cancelled (UAC prompt was declined).");
            }
        }

        private static void Emit(string message)
        {
            if (!s_quiet)
                Console.WriteLine(message);
        }

        private static int Fail(int code, string message)
        {
            Console.Error.WriteLine($"FAILED: {message}");
            Console.WriteLine($"RESULT=FAIL code={code}");
            return code;
        }

        private static void PrintUsage()
        {
            Console.WriteLine(
                """
                n1ssan injector — loads n1ssan-dll.dll into cs2.exe after the game has finished loading.

                Usage: n1ssan-injector [options]

                  --dll <path>           Inject this DLL (default: n1ssan-dll.dll found automatically)
                  --pid <pid>            Target an existing cs2.exe instead of detecting it
                  --wait <seconds>       How long to wait for CS2 to start (default 300, 0 = don't wait)
                  --inject-timeout <sec> How long LoadLibraryW may take inside CS2 (default 60)
                  --status-timeout <sec> How long to wait for the DLL's READY heartbeat (default 120)
                  --no-status            Skip waiting for the DLL status heartbeat
                  --no-deps              Skip the imported-DLL/function check
                  --skip-client-wait     Do not wait for client.dll (testing only)
                  --elevate              Relaunch elevated if Windows denies access
                  --quiet                Only print errors and the final RESULT line
                  -h, --help             Show this help
                  --version              Print the version

                Exit codes:
                  0    injected, or already loaded
                  2    bad arguments
                  3    DLL problem (missing, not x64, unmet dependency, MinHook missing)
                  4    CS2 not found, or it closed before injection
                  5    injection failed
                  6    the game unloaded the DLL immediately (Trusted Mode)
                  7    the DLL reported FAILED
                  8    injected, but no READY heartbeat within the timeout
                  130  cancelled

                CS2 must be started with -allow_third_party_software, otherwise Trusted Mode unloads
                third-party DLLs. n1ssan-dll.dll also needs MinHook.x64.dll in its own folder.
                """);
        }

        private sealed class Options
        {
            internal string? DllPath { get; private set; }
            internal uint? Pid { get; private set; }
            internal TimeSpan WaitForGame { get; private set; } = TimeSpan.FromSeconds(300);
            internal TimeSpan InjectTimeout { get; private set; } = TimeSpan.FromSeconds(60);
            internal TimeSpan StatusTimeout { get; private set; } = TimeSpan.FromSeconds(120);
            internal bool SkipStatus { get; private set; }
            internal bool SkipDependencyCheck { get; private set; }
            internal bool SkipClientWait { get; private set; }
            internal bool Elevate { get; private set; }
            internal bool Quiet { get; private set; }
            internal bool ShowHelp { get; private set; }
            internal bool ShowVersion { get; private set; }

            internal static Options Parse(string[] args)
            {
                var options = new Options();

                for (int i = 0; i < args.Length; i++)
                {
                    string argument = args[i];

                    switch (argument.ToLowerInvariant())
                    {
                        case "-h":
                        case "--help":
                        case "/?":
                            options.ShowHelp = true;
                            return options;

                        case "--version":
                            options.ShowVersion = true;
                            return options;

                        case "--dll":
                            options.DllPath = RequireValue(args, ref i, argument);
                            break;

                        case "--pid":
                            options.Pid = ParsePid(RequireValue(args, ref i, argument));
                            break;

                        case "--wait":
                            options.WaitForGame = ParseSeconds(RequireValue(args, ref i, argument), argument);
                            break;

                        case "--no-wait":
                            options.WaitForGame = TimeSpan.Zero;
                            break;

                        case "--inject-timeout":
                            options.InjectTimeout = ParseSeconds(RequireValue(args, ref i, argument), argument);
                            break;

                        case "--status-timeout":
                            options.StatusTimeout = ParseSeconds(RequireValue(args, ref i, argument), argument);
                            break;

                        case "--no-status":
                            options.SkipStatus = true;
                            break;

                        case "--no-deps":
                            options.SkipDependencyCheck = true;
                            break;

                        case "--skip-client-wait":
                            options.SkipClientWait = true;
                            break;

                        case "--elevate":
                            options.Elevate = true;
                            break;

                        case "--quiet":
                            options.Quiet = true;
                            break;

                        default:
                            throw new ArgumentException($"Unknown option '{argument}'. Use --help for the list.");
                    }
                }

                return options;
            }

            private static string RequireValue(string[] args, ref int index, string option)
            {
                if (index + 1 >= args.Length)
                    throw new ArgumentException($"{option} needs a value.");

                string value = args[++index];

                if (string.IsNullOrWhiteSpace(value))
                    throw new ArgumentException($"{option} needs a non-empty value.");

                return value;
            }

            private static uint ParsePid(string value)
            {
                if (!uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out uint pid) || pid == 0)
                    throw new ArgumentException($"'{value}' is not a valid process id.");

                return pid;
            }

            private static TimeSpan ParseSeconds(string value, string option)
            {
                if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int seconds) ||
                    seconds < 0 || seconds > 3600)
                {
                    throw new ArgumentException($"{option} expects a whole number of seconds between 0 and 3600.");
                }

                return TimeSpan.FromSeconds(seconds);
            }
        }
    }
}
