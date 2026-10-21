using Microsoft.Win32;
namespace Minseg.Core;

public static class InstalledPrograms
{
    public static Product? Hint(string name,string publisher="")
    {
        if(name.Contains("AnyDesk",StringComparison.OrdinalIgnoreCase)) return Product.AnyDesk;
        if(name.Contains("WPS Office",StringComparison.OrdinalIgnoreCase)||name.Contains("Kingsoft Office",StringComparison.OrdinalIgnoreCase)) return Product.Wps;
        return null;
    }
    public static IReadOnlyList<InstalledApp> Read(DeviceInfo device,List<string> warnings)
    {
        var result=new List<InstalledApp>();
        foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32})
        {
            ReadRoot(RegistryHive.LocalMachine,view,@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",true,result,warnings);
            if(device.UserSid.Length>0) ReadRoot(RegistryHive.Users,view,device.UserSid+@"\Software\Microsoft\Windows\CurrentVersion\Uninstall",false,result,warnings);
        }
        return Deduplicate(result);
    }
    public static IReadOnlyList<InstalledApp> Deduplicate(IEnumerable<InstalledApp> apps)
        =>apps.DistinctBy(LogicalEntry).ToArray();
    public static bool SameInstallation(InstalledApp first,InstalledApp second)=>LogicalEntry(first)==LogicalEntry(second);
    public static bool SameRegistryEntry(InstalledApp first,InstalledApp second)
        =>LogicalEntry(first).RegistryPath.Equals(LogicalEntry(second).RegistryPath,StringComparison.OrdinalIgnoreCase);
    public static InstalledApp? Revalidate(InstalledApp original,IReadOnlyList<InstalledApp> current)
    {
        var exact=current.SingleOrDefault(a=>a.RegistryPath.Equals(original.RegistryPath,StringComparison.OrdinalIgnoreCase));
        if(exact!=null)
        {
            if(!SameInstallation(exact,original))throw new IOException("La instalación cambió. Vuelve a analizar.");
            return exact;
        }
        var alias=current.SingleOrDefault(a=>SameInstallation(a,original));
        if(alias!=null)return alias;
        if(current.Any(a=>SameRegistryEntry(a,original)))throw new IOException("La instalación cambió. Vuelve a analizar.");
        return null;
    }
    private static InstalledApp LogicalEntry(InstalledApp app)
    {
        var parts=app.RegistryPath.Split('|',3);
        // Some uninstall keys are shared between the 32- and 64-bit views. Collapse only
        // identical values under the same hive/key; retain different versions, paths and scopes.
        return parts.Length==3?app with{RegistryPath=parts[0]+"|"+parts[2]}:app;
    }
    private static void ReadRoot(RegistryHive hive,RegistryView view,string path,bool machine,List<InstalledApp> result,List<string> warnings)
    {
        try
        {
            using var root=RegistryKey.OpenBaseKey(hive,view);using var key=root.OpenSubKey(path);
            if(key==null) return;
            foreach(var child in key.GetSubKeyNames())
            {
                using var app=key.OpenSubKey(child);if(app==null) continue;
                var name=app.GetValue("DisplayName") as string??"";var publisher=app.GetValue("Publisher") as string??"";
                var product=Hint(name,publisher);if(product==null) continue;
                var location=Environment.ExpandEnvironmentVariables(app.GetValue("InstallLocation") as string??"").Trim('"',' ');
                var uninstall=app.GetValue("UninstallString",null,RegistryValueOptions.DoNotExpandEnvironmentNames) as string??"";
                bool inferred=location.Length==0;
                if(location.Length==0) location=Path.GetDirectoryName(PathSafety.ExecutableFromCommand(uninstall)??"")??"";
                string? msi=(app.GetValue("WindowsInstaller") is int value&&value==1&&Guid.TryParseExact(child,"B",out var id))?id.ToString("B"):null;
                result.Add(new InstalledApp(product.Value,name,app.GetValue("DisplayVersion") as string??"",publisher,
                    $"{hive}|{view}|{path}\\{child}",location,uninstall,machine,msi,inferred,machine?null:path.Split('\\')[0]));
            }
        }
        catch(Exception ex) when(ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        { warnings.Add("No se pudo leer parte del registro de programas."); }
    }
    public static IReadOnlyList<InstalledApp> ReadAll(DeviceInfo device,IReadOnlyList<UserProfile> profiles,List<string> warnings)
    {
        var apps=Read(device,warnings).ToList();
        foreach(var profile in profiles.Where(p=>p.Sid!=device.UserSid))
        {
            try
            {
                using var hive=UserProfiles.Open(profile);
                foreach(var location in new[]{@"Software\Microsoft\Windows\CurrentVersion\Uninstall",@"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"})
                {
                    using var root=hive.OpenSubKey(location);if(root==null)continue;
                    foreach(var child in root.GetSubKeyNames())
                    {
                        using var key=root.OpenSubKey(child);if(key==null)throw new IOException("Entrada de instalación no accesible.");
                        var name=key.GetValue("DisplayName") as string??"";var product=Hint(name);if(product==null)continue;
                        var folder=UserProfiles.Expand(key.GetValue("InstallLocation",null,RegistryValueOptions.DoNotExpandEnvironmentNames) as string??"",profile).Trim('"',' ');
                        var command=UserProfiles.Expand(key.GetValue("UninstallString",null,RegistryValueOptions.DoNotExpandEnvironmentNames) as string??"",profile);
                        apps.Add(new(product.Value,name,key.GetValue("DisplayVersion") as string??"",key.GetValue("Publisher") as string??"",
                            $"Users|Registry64|{profile.Sid}\\{location}\\{child}",folder,command,false,LocationInferred:folder.Length==0,OwnerSid:profile.Sid));
                    }
                }
            }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException){warnings.Add("No se pudo comprobar la instalación en "+profile.Path+": "+ErrorDetails.Message(ex));}
        }
        return Deduplicate(apps);
    }
}
