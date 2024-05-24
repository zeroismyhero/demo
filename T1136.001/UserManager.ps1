Add-Type -AssemblyName "System.DirectoryServices.AccountManagement"
$dotNetCode = @"
using System;
using System.DirectoryServices.AccountManagement;

public class UserManager {
    public static void CreateUser(string username, string password) {
        using (var context = new PrincipalContext(ContextType.Machine)) {
            using (var user = new UserPrincipal(context)) {
                user.SamAccountName = username;
                user.SetPassword(password);
                user.Enabled = true;
                user.Save();
            }
        }
    }
}
"@
Add-Type -TypeDefinition $dotNetCode -ReferencedAssemblies "System.DirectoryServices.AccountManagement"
