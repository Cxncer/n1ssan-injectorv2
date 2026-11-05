using System;
using System.Collections.Generic;
using System.IO;

namespace n1ssan_injector
{
    internal sealed record ResolvedDll(string Path, string Source);

    /// <summary>
    /// Locates n1ssan-dll.dll, its MinHook companion, and the DLL status directory.
    /// Paths are returned absolute and fully qualified.
    /// </summary>
    internal static class InjectorConfig
    {
        internal const string DllName = "n1ssan-dll.dll";
        internal const string StatusFolder = "n1ssan";
        internal const string StatusSubfolder = "status";

        private static readonly string[] MinHookNames = { "MinHook.x64.dll", "minhook.dll", "MinHook.dll" };

        /// <summary>
        /// Search order:
        ///   1. an explicit --dll argument
        ///   2. N1SSAN_DLL_PATH
        ///   3. next to this executable
        ///   4. the CS2-n1ssan project layout, walking up from this executable
        ///   5. the same walk from the current working directory
        /// </summary>
        internal static ResolvedDll ResolveDllPath(string? explicitPath)
        {
            if (!string.IsNullOrWhiteSpace(explicitPath))
            {
                string full = Path.GetFullPath(explicitPath);

                if (!File.Exists(full))
                    throw new FileNotFoundException($"The --dll path does not exist: {full}");

                return new ResolvedDll(full, "--dll argument");
            }

            string? fromEnvironment = Environment.GetEnvironmentVariable("N1SSAN_DLL_PATH");
            if (!string.IsNullOrWhiteSpace(fromEnvironment))
            {
                string full = Path.GetFullPath(fromEnvironment);

                if (!File.Exists(full))
                    throw new FileNotFoundException($"N1SSAN_DLL_PATH is set but does not point to a file: {full}");

                return new ResolvedDll(full, "N1SSAN_DLL_PATH");
            }

            string baseDirectory = AppContext.BaseDirectory;
            string beside = Path.Combine(baseDirectory, DllName);
            if (File.Exists(beside))
                return new ResolvedDll(Path.GetFullPath(beside), "next to the injector");

            foreach (string start in new[] { baseDirectory, Directory.GetCurrentDirectory() })
            {
                string? found = WalkUpForProjectLayout(start);
                if (found != null)
                    return new ResolvedDll(found, "CS2-n1ssan build output");
            }

            throw new FileNotFoundException(
                $"Could not locate {DllName}. Build CS2-n1ssan for x64 Release, put the DLL next to this injector, " +
                "or pass --dll <path>.");
        }

        private static string? WalkUpForProjectLayout(string startDirectory)
        {
            DirectoryInfo? directory;

            try
            {
                directory = new DirectoryInfo(Path.GetFullPath(startDirectory));
            }
            catch (Exception)
            {
                return null;
            }

            for (int depth = 0; directory != null && depth < 8; depth++, directory = directory.Parent)
            {
                foreach (string relative in ProjectLayouts())
                {
                    string candidate = Path.Combine(directory.FullName, relative);
                    if (File.Exists(candidate))
                        return Path.GetFullPath(candidate);
                }
            }

            return null;
        }

        private static IEnumerable<string> ProjectLayouts()
        {
            yield return DllName;
            yield return Path.Combine("x64", "Release", DllName);
            yield return Path.Combine("CS2-n1ssan", "x64", "Release", DllName);
            yield return Path.Combine("CS2-n1ssan", "x64", "Debug", DllName);
            yield return Path.Combine("n1ssan-dll", "x64", "Release", DllName);
        }

        /// <summary>
        /// n1ssan-dll.dll loads MinHook at runtime from its own folder, so the x64 MinHook DLL must sit
        /// beside it. Returns the MinHook path that was found.
        /// </summary>
        internal static string VerifyMinHook(string dllDirectory, out List<string> problems)
        {
            problems = new List<string>();

            foreach (string name in MinHookNames)
            {
                string path = Path.Combine(dllDirectory, name);
                if (!File.Exists(path))
                    continue;

                DllInspector.Result inspection = DllInspector.Inspect(path, checkDependencies: false);
                if (!inspection.IsValid)
                {
                    problems.Add($"{name} is not a usable x64 DLL:");
                    problems.AddRange(inspection.Problems);
                    continue;
                }

                return path;
            }

            problems.Add($"MinHook is missing from {dllDirectory}.");
            problems.Add("n1ssan-dll.dll loads MinHook at runtime; without it the DLL reports FAILED (minhook_load_failed).");
            problems.Add($"Copy MinHook.x64.dll next to {DllName}.");

            return string.Empty;
        }

        /// <summary>%LOCALAPPDATA%\n1ssan\status, with the same temp fallback the DLL uses.</summary>
        internal static string StatusDirectory()
        {
            string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            if (string.IsNullOrWhiteSpace(root))
                root = Path.GetTempPath();

            return Path.Combine(root, StatusFolder, StatusSubfolder);
        }

        internal static string StatusFile(uint pid)
            => Path.Combine(StatusDirectory(), $"cs2-{pid}.status");
    }
}
