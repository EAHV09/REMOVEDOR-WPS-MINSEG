using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Minseg.Core;

public sealed record UserProfile(string Sid,string Path);
public static class UserProfiles
{
    public static IReadOnlyList<UserProfile> Read(DeviceInfo device,List<string> warnings)
    {
        var result=new List<UserProfile>();
        if(SafetyRules.IsLocalPath(device.ProfilePath)&&device.UserSid.Length>0)result.Add(new(device.UserSid,device.ProfilePath));
        try
        {
            using var list=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")??throw new IOException("Perfiles no disponibles.");
            foreach(var sid in list.GetSubKeyNames().Where(s=>s.StartsWith("S-1-5-21-",StringComparison.Ordinal)||s.StartsWith("S-1-12-1-",StringComparison.Ordinal)))
            {
                using var key=list.OpenSubKey(sid);
                var path=Environment.ExpandEnvironmentVariables(key?.GetValue("ProfileImagePath") as string??"");
                if(!SafetyRules.IsLocalPath(path)){warnings.Add("Perfil sin ruta local comprobable: "+sid);continue;}
                try{PathSafety.RequireNoReparse(path);result.Add(new(sid,System.IO.Path.GetFullPath(path)));}
                catch(Exception ex)when(ex is IOException or UnauthorizedAccessException){warnings.Add("No se pudo revisar el perfil "+path+": "+ErrorDetails.Message(ex));}
            }
        }
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException){warnings.Add("No se pudieron enumerar todos los perfiles: "+ErrorDetails.Message(ex));}
        return result.DistinctBy(p=>p.Sid,StringComparer.OrdinalIgnoreCase).ToArray();
    }
    internal static RegistryKey Open(UserProfile profile,bool writable=false)
    {
        if(!profile.Sid.StartsWith("S-1-",StringComparison.Ordinal)||profile.Sid.Contains('\\'))throw new IOException("Perfil no válido.");
        var loaded=Registry.Users.OpenSubKey(profile.Sid,writable);
        if(loaded!=null)return loaded;
        // A private application hive is unloaded when its last handle closes. No global mount or ACL changes.
        if(writable&&!deviceAdministrator())throw new UnauthorizedAccessException("Se necesitan permisos de administrador para este perfil.");
        var file=System.IO.Path.Combine(profile.Path,"NTUSER.DAT");return OpenPrivate(file,writable);
    }
    internal static RegistryKey? OpenClasses(UserProfile profile,bool writable=false)
    {
        if(!profile.Sid.StartsWith("S-1-",StringComparison.Ordinal)||profile.Sid.Contains('\\'))throw new IOException("Perfil no válido.");
        var loaded=Registry.Users.OpenSubKey(profile.Sid+"_Classes",writable);if(loaded!=null)return loaded;
        var file=System.IO.Path.Combine(profile.Path,@"AppData\Local\Microsoft\Windows\UsrClass.dat");
        try{File.GetAttributes(file);}catch(Exception ex)when(ex is FileNotFoundException or DirectoryNotFoundException){return null;}
        if(writable&&!deviceAdministrator())throw new UnauthorizedAccessException("Se necesitan permisos de administrador para este perfil.");
        return OpenPrivate(file,writable);
    }
    private static RegistryKey OpenPrivate(string file,bool writable)
    {
        PathSafety.RequireNoReparse(file);
        int status=RegLoadAppKey(file,out var handle,writable?0x2001fu:0x20019u,1,0);
        if(status!=0){handle?.Dispose();throw new IOException("No se pudo leer el registro del perfil: "+file,new Win32Exception(status));}
        return RegistryKey.FromHandle(handle);
    }
    private static bool deviceAdministrator()=>DeviceInventory.IsAdministrator;
    internal static string Expand(string value,UserProfile profile)
        =>value.Replace("%USERPROFILE%",profile.Path,StringComparison.OrdinalIgnoreCase)
            .Replace("%LOCALAPPDATA%",System.IO.Path.Combine(profile.Path,@"AppData\Local"),StringComparison.OrdinalIgnoreCase)
            .Replace("%APPDATA%",System.IO.Path.Combine(profile.Path,@"AppData\Roaming"),StringComparison.OrdinalIgnoreCase);
    [DllImport("advapi32.dll",EntryPoint="RegLoadAppKeyW",CharSet=CharSet.Unicode)]
    private static extern int RegLoadAppKey(string file,out SafeRegistryHandle handle,uint access,uint options,uint reserved);
}
