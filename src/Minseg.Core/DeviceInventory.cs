using Microsoft.Win32;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Minseg.Core;

public static class DeviceInventory
{
    public static bool IsAdministrator => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    public static DeviceInfo Read()
    {
        using var identity=WindowsIdentity.GetCurrent();
        int session=Process.GetCurrentProcess().SessionId;
        var user=SessionText(session,5); var domain=SessionText(session,7);
        var account=string.IsNullOrEmpty(user)?"No identificado":string.IsNullOrEmpty(domain)?user:domain+"\\"+user;
        var sid=""; var profile="";
        try
        {
            if (!string.IsNullOrEmpty(user)) sid=((SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier))).Value;
            using var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\"+sid);
            profile=Environment.ExpandEnvironmentVariables(key?.GetValue("ProfileImagePath") as string??"");
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or System.Security.SecurityException or UnauthorizedAccessException) { }
        using var windows=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        var release=windows?.GetValue("DisplayVersion")?.ToString()??"";
        var build=windows?.GetValue("CurrentBuildNumber")?.ToString()??Environment.OSVersion.Version.Build.ToString();
        var version=(int.TryParse(build,out var number)&&number>=22000?"Windows 11":"Windows 10")+" "+release+" · "+build;
        var adapters=NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.NetworkInterfaceType!=NetworkInterfaceType.Loopback)
            .Select(n=>new NetworkAdapter(n.Name,n.NetworkInterfaceType.ToString(),n.OperationalStatus.ToString(),
                string.Join(", ",n.GetIPProperties().UnicastAddresses.Select(a=>a.Address.ToString())),
                string.Join(":",n.GetPhysicalAddress().GetAddressBytes().Select(b=>b.ToString("X2"))))).ToArray();
        return new DeviceInfo(Environment.MachineName,version,RuntimeInformation.OSArchitecture.ToString(),account,sid,profile,
            identity.Name,IsAdministrator,session,adapters);
    }

    private static string SessionText(int session,int information)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero,session,information,out var buffer,out var size)) return "";
        try { return size>2?Marshal.PtrToStringUni(buffer)??"":""; }
        finally { WTSFreeMemory(buffer); }
    }
    [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool WTSQuerySessionInformation(IntPtr server,int session,int info,out IntPtr buffer,out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr memory);
}
