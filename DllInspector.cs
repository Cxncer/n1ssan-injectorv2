using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace n1ssan_injector
{
    /// <summary>
    /// Reads the payload DLL before injection: confirms it is a 64-bit PE image and checks that every
    /// imported DLL and function exists on this PC. A missing dependency is the most common reason an
    /// otherwise correct injection fails inside CS2 with "module not found".
    /// </summary>
    internal static class DllInspector
    {
        internal sealed record Result(bool IsValid, List<string> Problems, List<string> MissingDependencies, int ImportedDllCount, int ImportedFunctionCount, bool LooksQuarantined = false);

        internal static Result Inspect(string dllPath, bool checkDependencies)
        {
            var problems = new List<string>();
            var missing = new List<string>();
            int importedDlls = 0;
            int importedFunctions = 0;

            byte[] image;
            try
            {
                image = File.ReadAllBytes(dllPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                problems.Add($"The DLL can't be read ({ex.GetType().Name}: {ex.Message}). An antivirus may be holding or quarantining it.");
                return new Result(false, problems, missing, 0, 0, LooksQuarantined: true);
            }

            if (image.Length < 0x200)
            {
                problems.Add($"The DLL is only {image.Length} bytes; it is not a valid PE image (antivirus quarantine?).");
                return new Result(false, problems, missing, 0, 0, LooksQuarantined: true);
            }

            if (image[0] != (byte)'M' || image[1] != (byte)'Z')
            {
                problems.Add("The DLL has no MZ header; the file is not a Windows PE image.");
                return new Result(false, problems, missing, 0, 0);
            }

            int peOffset = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
            if (peOffset <= 0 || peOffset + 24 > image.Length)
            {
                problems.Add("The DLL's PE header offset is outside the file; the file is damaged.");
                return new Result(false, problems, missing, 0, 0);
            }

            if (BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(peOffset)) != 0x00004550)
            {
                problems.Add("The DLL has no PE signature; the file is damaged.");
                return new Result(false, problems, missing, 0, 0);
            }

            int fileHeader = peOffset + 4;
            ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(fileHeader));
            ushort numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(fileHeader + 2));
            ushort optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(fileHeader + 16));
            ushort characteristics = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(fileHeader + 18));

            int optionalHeader = fileHeader + 20;
            if (optionalHeader + 112 > image.Length)
            {
                problems.Add("The DLL's optional header is truncated.");
                return new Result(false, problems, missing, 0, 0);
            }

            ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(optionalHeader));
            if (magic != 0x20B)
                problems.Add($"The DLL is not a 64-bit PE image (optional header magic 0x{magic:X3}). CS2 is 64-bit; build n1ssan-dll for x64.");
            else if (machine != 0x8664)
                problems.Add($"The DLL's machine type is 0x{machine:X4}, expected 0x8664 (x86-64).");
            else if ((characteristics & 0x2000) == 0)
                problems.Add("The file is an executable, not a DLL (IMAGE_FILE_DLL is not set).");

            if (problems.Count > 0)
                return new Result(false, problems, missing, 0, 0);

            if (!checkDependencies)
                return new Result(true, problems, missing, 0, 0);

            try
            {
                var sections = ReadSections(image, optionalHeader + optionalHeaderSize, numberOfSections);
                ScanImports(image, optionalHeader, sections, missing, ref importedDlls, ref importedFunctions);
            }
            catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentOutOfRangeException or OverflowException)
            {
                // A malformed import table is not automatically fatal; let LoadLibrary try.
                problems.Add("The DLL's import table could not be parsed; dependency checks were skipped.");
            }

            return new Result(true, problems, missing, importedDlls, importedFunctions);
        }

        private readonly record struct Section(uint VirtualAddress, uint VirtualSize, uint RawSize, uint RawPointer)
        {
            internal bool Contains(uint rva) => rva >= VirtualAddress && rva < VirtualAddress + Math.Max(VirtualSize, RawSize);
            internal bool IsRaw => RawPointer != 0;
        }

        private static List<Section> ReadSections(byte[] image, int tableOffset, ushort count)
        {
            var sections = new List<Section>(count);

            for (int i = 0; i < count; i++)
            {
                int offset = tableOffset + i * 40;
                if (offset + 40 > image.Length)
                    break;

                uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(offset + 8));
                uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(offset + 12));
                uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(offset + 16));
                uint rawPointer = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(offset + 20));

                sections.Add(new Section(virtualAddress, virtualSize, rawSize, rawPointer));
            }

            return sections;
        }

        private static long RvaToOffset(uint rva, List<Section> sections, int imageLength)
        {
            foreach (Section section in sections)
            {
                if (!section.IsRaw || !section.Contains(rva))
                    continue;

                long offset = (long)rva - section.VirtualAddress + section.RawPointer;
                return offset > 0 && offset < imageLength ? offset : -1;
            }

            return -1;
        }

        private static void ScanImports(byte[] image, int optionalHeader, List<Section> sections, List<string> missing, ref int dllCount, ref int functionCount)
        {
            uint directoryCount = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(optionalHeader + 108));
            if (directoryCount <= 1)
                return;

            uint importRva = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(optionalHeader + 112 + 8));
            if (importRva == 0)
                return;

            long descriptorOffset = RvaToOffset(importRva, sections, image.Length);
            if (descriptorOffset < 0)
                return;

            var importedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (int index = 0; index < 512; index++)
            {
                long offset = descriptorOffset + index * 20L;
                if (offset + 20 > image.Length)
                    break;

                uint originalFirstThunk = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)offset));
                uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)offset + 12));
                uint firstThunk = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)offset + 16));

                if (nameRva == 0)
                    break;

                long nameOffset = RvaToOffset(nameRva, sections, image.Length);
                if (nameOffset < 0)
                    continue;

                string? moduleName = ReadNullTerminatedAscii(image, (int)nameOffset);
                if (string.IsNullOrEmpty(moduleName))
                    continue;

                if (!importedNames.Add(moduleName))
                    continue;

                dllCount++;

                IntPtr module = NativeMethods.GetModuleHandleW(moduleName);
                bool owned = false;

                if (module == IntPtr.Zero)
                {
                    module = NativeMethods.LoadLibraryW(moduleName);
                    owned = module != IntPtr.Zero;
                }

                if (module == IntPtr.Zero)
                {
                    missing.Add(moduleName);
                    continue;
                }

                try
                {
                    uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
                    long thunkOffset = RvaToOffset(thunkRva, sections, image.Length);
                    if (thunkOffset < 0)
                        continue;

                    for (int thunkIndex = 0; thunkIndex < 5000; thunkIndex++)
                    {
                        long entry = thunkOffset + thunkIndex * 8L;
                        if (entry + 8 > image.Length)
                            break;

                        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan((int)entry));
                        if (value == 0)
                            break;

                        if ((value & 0x8000000000000000UL) != 0)
                            continue; // imported by ordinal

                        long hintOffset = RvaToOffset((uint)value, sections, image.Length);
                        if (hintOffset < 0 || hintOffset + 2 >= image.Length)
                            continue;

                        string? functionName = ReadNullTerminatedAscii(image, (int)hintOffset + 2);
                        if (string.IsNullOrEmpty(functionName))
                            continue;

                        functionCount++;

                        if (NativeMethods.GetProcAddress(module, functionName) == IntPtr.Zero)
                            missing.Add($"{moduleName} -> {functionName}");
                    }
                }
                finally
                {
                    if (owned)
                        NativeMethods.FreeLibrary(module);
                }
            }
        }

        private static string? ReadNullTerminatedAscii(byte[] image, int offset)
        {
            if (offset < 0 || offset >= image.Length)
                return null;

            int end = offset;
            while (end < image.Length && image[end] != 0 && end - offset < 512)
                end++;

            return end == offset ? null : System.Text.Encoding.ASCII.GetString(image, offset, end - offset);
        }
    }
}
