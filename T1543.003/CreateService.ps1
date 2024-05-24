Add-Type -AssemblyName "System.ServiceProcess"

$dotNetServiceCode = @"
using System;
using System.ServiceProcess;
using System.Runtime.InteropServices;

public class ServiceManager {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);
    
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    private static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName, uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword);
    
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    public static void CreateService(string serviceName, string binPath) {
        IntPtr scmHandle = OpenSCManager(null, null, 0xF003F);
        if (scmHandle == IntPtr.Zero) throw new Exception("OpenSCManager failed");

        IntPtr serviceHandle = CreateService(scmHandle, serviceName, serviceName, 0xF01FF, 0x10, 0x2, 0x1, binPath, null, IntPtr.Zero, null, null, null);
        if (serviceHandle == IntPtr.Zero) throw new Exception("CreateService failed");

        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);
    }
}
"@

Add-Type -TypeDefinition $dotNetServiceCode -ReferencedAssemblies "System.ServiceProcess"
