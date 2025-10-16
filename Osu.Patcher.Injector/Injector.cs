using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using HoLLy.ManagedInjector;

namespace Osu.Patcher.Injector
{
    internal static class Injector
    {
        public static void Main(string[] args)
        {
            try
            {
                uint pid = args.Length > 0 && uint.TryParse(args[0], out var parsedPid)
                    ? parsedPid
                    : throw new ArgumentException("Please provide a PID as an argument.");

                using var process = Process.GetProcessById((int)pid);

                string cmdline = GetCommandLineSafe(process);

                if (!cmdline.Contains("-devserver"))
                {
                    Console.WriteLine("Process does not have '-devserver' in the command line. Skipping injection.");
                    return;
                }
                if (cmdline.Contains("ppy.sh"))
                {
                    Console.WriteLine("Process command line contains 'ppy.sh'. Skipping injection.");
                    return;
                }

                using var proc = new InjectableProcess(pid);
                var dllPath = Path.GetFullPath(typeof(Injector).Assembly.Location + @"\..\osu!.hook.dll");

                proc.Inject(dllPath, "Osu.Patcher.Hook.Hook", "Initialize");
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e);
                Console.WriteLine("\nPress any key to continue...");
                Console.Write("\a");
                Console.ReadKey();
            }
        }

        private static string GetCommandLine(Process process)
        {
            var hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);
            if (hProcess == IntPtr.Zero)
                throw new InvalidOperationException("Cannot open process.");

            try
            {
                var pbi = new PROCESS_BASIC_INFORMATION();
                int status = NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out _);
                if (status != 0) throw new Exception("NtQueryInformationProcess failed.");

                IntPtr pebAddress = pbi.PebBaseAddress;
                ReadProcessMemory(hProcess, pebAddress + 0x20, out IntPtr procParams, IntPtr.Size, out _);
                ReadProcessMemory(hProcess, procParams + 0x70, out UNICODE_STRING cmdLine, Marshal.SizeOf<UNICODE_STRING>(), out _);

                byte[] buffer = new byte[cmdLine.Length];
                ReadProcessMemory(hProcess, cmdLine.Buffer, buffer, buffer.Length, out _);

                return Encoding.Unicode.GetString(buffer);
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }
        private static string GetCommandLineSafe(Process process)
        {
            var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, process.Id);
            if (hProcess == IntPtr.Zero)
                throw new InvalidOperationException("Cannot open process.");

            try
            {
                int PROCESSINFOCLASS_ProcessCommandLineInformation = 60; // Windows 8+

                int returnLength;
                int status = NtQueryInformationProcess(
                    hProcess,
                    PROCESSINFOCLASS_ProcessCommandLineInformation,
                    IntPtr.Zero,
                    0,
                    out returnLength);

                if (status != STATUS_INFO_LENGTH_MISMATCH)
                    throw new Exception($"Initial NtQueryInformationProcess failed: 0x{status:X}");

                IntPtr buffer = Marshal.AllocHGlobal(returnLength);
                try
                {
                    status = NtQueryInformationProcess(
                        hProcess,
                        PROCESSINFOCLASS_ProcessCommandLineInformation,
                        buffer,
                        returnLength,
                        out _);

                    if (status != 0)
                        throw new Exception($"NtQueryInformationProcess failed: 0x{status:X}");

                    UNICODE_STRING commandLine = Marshal.PtrToStructure<UNICODE_STRING>(buffer);
                    return Marshal.PtrToStringUni(commandLine.Buffer, commandLine.Length / 2);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }
        private const int PROCESS_QUERY_INFORMATION = 0x0400;
        private const int PROCESS_VM_READ = 0x0010;
        private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
        private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(
            IntPtr hProcess,
            int processInformationClass,
            IntPtr processInformation,
            int processInformationLength,
            out int returnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr hProcess, int processInformationClass, ref PROCESS_BASIC_INFORMATION pbi, int cb, out int pSize);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int access, bool inheritHandle, int pid);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr baseAddress, out IntPtr buffer, int size, out int read);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr baseAddress, out UNICODE_STRING buffer, int size, out int read);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr baseAddress, byte[] buffer, int size, out int read);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr processHandle, out bool isWow64);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniquePid;
            public IntPtr Reserved3;
        }
    }
}
