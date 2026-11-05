using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace n1ssan_injector
{
    internal enum InjectStatus
    {
        Success,
        ProcessNotFound,
        AccessDenied,
        AllocationFailed,
        WriteFailed,
        ThreadCreationFailed,
        LoadFailed,
        Timeout,
        Cancelled,
    }

    internal sealed record InjectOutcome(InjectStatus Status, int Win32Error, string Message)
    {
        internal bool Ok => Status == InjectStatus.Success;
    }

    /// <summary>
    /// Loads a 64-bit DLL into a running target with the classic
    /// VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryW) technique.
    ///
    /// The remote thread runs a small x64 stub rather than LoadLibraryW directly, so a failure
    /// returns the real GetLastError() code instead of a bare NULL exit code. The stub and the
    /// DLL path share one allocation; nothing is freed while the remote thread might still run.
    /// </summary>
    internal sealed class DllInjector
    {
        private readonly string _dllPath;
        private readonly byte[] _dllPathBytes;

        internal DllInjector(string dllPath)
        {
            if (!File.Exists(dllPath))
                throw new FileNotFoundException("The DLL to inject does not exist.", dllPath);

            if (!Environment.Is64BitProcess)
                throw new PlatformNotSupportedException(
                    "The injector must run as a 64-bit process to load a 64-bit DLL into CS2.");

            _dllPath = Path.GetFullPath(dllPath);
            _dllPathBytes = Encoding.Unicode.GetBytes(_dllPath + "\0");
        }

        internal async Task<InjectOutcome> InjectAsync(uint pid, TimeSpan threadTimeout, CancellationToken ct)
        {
            if (pid == 0)
                return Fail(InjectStatus.ProcessNotFound, 0, "No target process id was supplied.");

            const uint access =
                NativeMethods.PROCESS_CREATE_THREAD |
                NativeMethods.PROCESS_QUERY_INFORMATION |
                NativeMethods.PROCESS_VM_OPERATION |
                NativeMethods.PROCESS_VM_WRITE |
                NativeMethods.PROCESS_VM_READ;

            IntPtr process = NativeMethods.OpenProcess(access, false, pid);
            if (process == IntPtr.Zero)
            {
                int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();

                return error switch
                {
                    NativeMethods.ERROR_ACCESS_DENIED or NativeMethods.ERROR_INVALID_PARAMETER =>
                        Fail(InjectStatus.AccessDenied, error,
                            "Windows denied access to cs2.exe. If CS2 runs elevated, run this injector as administrator too."),
                    _ => Fail(InjectStatus.ProcessNotFound, error,
                            $"cs2.exe (PID {pid}) is gone: {Describe(error)}"),
                };
            }

            try
            {
                if (!GameProcess.IsAlive(pid))
                    return Fail(InjectStatus.ProcessNotFound, 0, $"cs2.exe (PID {pid}) exited before injection started.");

                return await InjectCoreAsync(process, pid, threadTimeout, ct).ConfigureAwait(false);
            }
            finally
            {
                NativeMethods.CloseHandle(process);
            }
        }

        private async Task<InjectOutcome> InjectCoreAsync(IntPtr process, uint pid, TimeSpan threadTimeout, CancellationToken ct)
        {
            // [ UTF-16 DLL path | padding | x64 loader stub ] in a single remote allocation.
            int pathBytes = _dllPathBytes.Length;
            int stubOffset = (pathBytes + 15) & ~15;
            const int stubCapacity = 128;

            IntPtr remote = NativeMethods.VirtualAllocEx(
                process, IntPtr.Zero, (nuint)(stubOffset + stubCapacity),
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
                NativeMethods.PAGE_EXECUTE_READWRITE);

            if (remote == IntPtr.Zero)
            {
                int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                return Fail(InjectStatus.AllocationFailed, error,
                    $"Could not allocate memory in cs2.exe: {Describe(error)}");
            }

            bool remoteOwned = true;

            try
            {
                IntPtr remotePath = remote;
                IntPtr remoteStub = IntPtr.Add(remote, stubOffset);

                IntPtr loadLibrary = ResolveExport("kernel32.dll", "LoadLibraryW");
                IntPtr getLastError = ResolveExport("kernel32.dll", "GetLastError");

                if (loadLibrary == IntPtr.Zero || getLastError == IntPtr.Zero)
                {
                    return Fail(InjectStatus.LoadFailed, 0,
                        "This injector could not resolve kernel32!LoadLibraryW / GetLastError.");
                }

                byte[] stub = BuildLoaderStub(
                    (ulong)remotePath.ToInt64(),
                    (ulong)loadLibrary.ToInt64(),
                    (ulong)getLastError.ToInt64());

                if (!WriteRemote(process, remotePath, _dllPathBytes, out int writeError))
                    return Fail(InjectStatus.WriteFailed, writeError, $"Could not write the DLL path into cs2.exe: {Describe(writeError)}");

                if (!WriteRemote(process, remoteStub, stub, out writeError))
                    return Fail(InjectStatus.WriteFailed, writeError, $"Could not write the loader stub into cs2.exe: {Describe(writeError)}");

                NativeMethods.FlushInstructionCache(process, remoteStub, (nuint)stub.Length);

                IntPtr thread = NativeMethods.CreateRemoteThread(
                    process, IntPtr.Zero, 0, remoteStub, IntPtr.Zero, 0, out _);

                if (thread == IntPtr.Zero)
                {
                    int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                    return Fail(InjectStatus.ThreadCreationFailed, error,
                        $"Could not create a remote thread in cs2.exe: {Describe(error)}");
                }

                try
                {
                    uint wait = await WaitAsync(thread, threadTimeout, ct).ConfigureAwait(false);

                    if (wait == NativeMethods.WAIT_TIMEOUT)
                    {
                        // The thread may still be inside LoadLibraryW (antivirus scan, hidden error box).
                        // Keep the remote block allocated: freeing it now would crash CS2.
                        remoteOwned = false;
                        return Fail(InjectStatus.Timeout, 0,
                            $"CS2 has been loading the DLL for {threadTimeout.TotalSeconds:0} seconds. " +
                            "Alt-Tab and look for an error/antivirus window behind the game. Do not close this window yet.");
                    }

                    if (wait == NativeMethods.WAIT_FAILED)
                    {
                        int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                        return Fail(InjectStatus.ThreadCreationFailed, error,
                            $"Waiting on the remote thread failed: {Describe(error)}");
                    }

                    if (!NativeMethods.GetExitCodeThread(thread, out uint exitCode))
                    {
                        int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                        return Fail(InjectStatus.LoadFailed, error, $"Could not read the loader result: {Describe(error)}");
                    }

                    if (exitCode != 0)
                    {
                        string explanation = ExplainLoadError((int)exitCode);
                        string message = $"CS2 could not load {Path.GetFileName(_dllPath)}: {Describe((int)exitCode)}";

                        if (explanation.Length > 0)
                            message += $"{Environment.NewLine}    -> {explanation}";

                        return Fail(InjectStatus.LoadFailed, (int)exitCode, message);
                    }

                    return new InjectOutcome(InjectStatus.Success, 0, $"DLL loaded into cs2.exe (PID {pid}).");
                }
                finally
                {
                    NativeMethods.CloseHandle(thread);
                }
            }
            finally
            {
                if (remoteOwned)
                    NativeMethods.VirtualFreeEx(process, remote, 0, NativeMethods.MEM_RELEASE);
            }
        }

        private static async Task<uint> WaitAsync(IntPtr thread, TimeSpan timeout, CancellationToken ct)
        {
            var stopwatch = Stopwatch.StartNew();

            while (stopwatch.Elapsed < timeout)
            {
                ct.ThrowIfCancellationRequested();

                uint result = NativeMethods.WaitForSingleObject(thread, 0);
                if (result != NativeMethods.WAIT_TIMEOUT)
                    return result;

                await Task.Delay(100, ct).ConfigureAwait(false);
            }

            return NativeMethods.WAIT_TIMEOUT;
        }

        private static bool WriteRemote(IntPtr process, IntPtr address, byte[] bytes, out int error)
        {
            bool ok = NativeMethods.WriteProcessMemory(
                process, address, bytes, (nuint)bytes.Length, out _);

            error = ok ? 0 : System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            return ok;
        }

        private static IntPtr ResolveExport(string moduleName, string exportName)
        {
            IntPtr module = NativeMethods.GetModuleHandleW(moduleName);
            return module == IntPtr.Zero ? IntPtr.Zero : NativeMethods.GetProcAddress(module, exportName);
        }

        /// <summary>
        /// x64 stub: LoadLibraryW(path); return 0 on success, GetLastError() on failure.
        ///   sub rsp,28h / mov rcx,path / mov rax,LoadLibraryW / call rax / test rax,rax
        ///   jz fail / xor eax,eax / add rsp,28h / ret
        ///   fail: mov rax,GetLastError / call rax / add rsp,28h / ret
        /// </summary>
        internal static byte[] BuildLoaderStub(ulong dllPathAddress, ulong loadLibraryAddress, ulong getLastErrorAddress)
        {
            var code = new System.Collections.Generic.List<byte>(64)
            {
                0x48, 0x83, 0xEC, 0x28,             // sub rsp, 28h
                0x48, 0xB9,                          // mov rcx, imm64
            };
            AppendUInt64(code, dllPathAddress);
            code.AddRange(new byte[] { 0x48, 0xB8 }); // mov rax, imm64
            AppendUInt64(code, loadLibraryAddress);
            code.AddRange(new byte[]
            {
                0xFF, 0xD0,                          // call rax
                0x48, 0x85, 0xC0,                    // test rax, rax
                0x74, 0x07,                          // jz fail (7 bytes ahead)
                0x31, 0xC0,                          // xor eax, eax
                0x48, 0x83, 0xC4, 0x28,              // add rsp, 28h
                0xC3,                                // ret
                0x48, 0xB8,                          // fail: mov rax, imm64
            });
            AppendUInt64(code, getLastErrorAddress);
            code.AddRange(new byte[]
            {
                0xFF, 0xD0,                          // call rax
                0x48, 0x83, 0xC4, 0x28,              // add rsp, 28h
                0xC3,                                // ret
            });

            return code.ToArray();
        }

        private static void AppendUInt64(System.Collections.Generic.List<byte> buffer, ulong value)
        {
            for (int i = 0; i < 8; i++)
                buffer.Add((byte)(value >> (i * 8)));
        }

        private static InjectOutcome Fail(InjectStatus status, int error, string message)
            => new(status, error, message);

        internal static string Describe(int code)
        {
            if (code == 0)
                return "no error";

            string system = new Win32Exception(code).Message;
            return $"{system} ({code})";
        }

        /// <summary>Plain-language cause and next step for LoadLibraryW failures inside CS2.</summary>
        internal static string ExplainLoadError(int code)
        {
            return code switch
            {
                NativeMethods.ERROR_FILE_NOT_FOUND or NativeMethods.ERROR_PATH_NOT_FOUND =>
                    "The DLL file disappeared - almost always an antivirus deleting or quarantining it.",
                NativeMethods.ERROR_ACCESS_DENIED =>
                    "Access denied - an antivirus or security tool is blocking the DLL.",
                NativeMethods.ERROR_MOD_NOT_FOUND =>
                    "A DLL that n1ssan-dll.dll needs is not on this PC (usually the Visual C++ runtime).",
                NativeMethods.ERROR_PROC_NOT_FOUND =>
                    "This Windows is missing an API n1ssan-dll.dll imports; run Windows Update.",
                NativeMethods.ERROR_BAD_EXE_FORMAT =>
                    "The file is damaged or not a 64-bit DLL.",
                NativeMethods.ERROR_VIRUS_INFECTED or NativeMethods.ERROR_VIRUS_DELETED =>
                    "Windows Defender (or another antivirus) flagged the DLL and blocked it.",
                NativeMethods.ERROR_INVALID_IMAGE_HASH =>
                    "Windows code-integrity policy (Smart App Control / WDAC) blocked the unsigned DLL.",
                NativeMethods.ERROR_DLL_INIT_FAILED =>
                    "DllMain in n1ssan-dll.dll failed while starting; check n1ssalogs.md next to the DLL.",
                4551 or 4553 or 4556 =>
                    "Windows system-integrity policy blocked the DLL (Smart App Control).",
                _ => string.Empty,
            };
        }

        internal static string AntivirusHint(string dllDirectory)
        {
            return "If Windows Security is involved: Virus & threat protection -> Manage settings -> Exclusions -> " +
                   $"add the folder {dllDirectory} and the folder holding this injector, then try again.";
        }
    }
}
