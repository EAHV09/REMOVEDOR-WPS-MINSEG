using Microsoft.Win32;
using System.Security.Cryptography;
using System.Text.Json;
using System.Runtime.InteropServices;
namespace Minseg.Core;

internal static class ExplorerResidues
{
    internal const string Marker="explorer-value|";
    internal static bool MatchesSnapshot(string content,string expected,UserProfile? profile=null)
    {
        var raw=SnapshotString(content);
        return raw!=null&&(profile==null?raw:UserProfiles.Expand(raw,profile))==expected;
    }
    private static string? SnapshotString(string content)
    {
        using var json=JsonDocument.Parse(content);var value=json.RootElement.GetProperty("Value");
        return value.ValueKind==JsonValueKind.String?value.GetString():null;
    }
    internal static bool CanReuse(Finding prior,string location,string content)
    {
        if(!IsFinding(prior)||prior.Trust!=Trust.Confirmed||prior.Location!=location||prior.ContentHash!=RegistryResidues.Hash(content))return false;
        var edit=JsonSerializer.Deserialize<ExplorerEdit>(prior.Reference![Marker.Length..]);
        return edit!=null&&Allowed(edit)&&MatchesSnapshot(content,edit.Expected);
    }
    internal static bool IsFinding(Finding f)=>f.Product==Product.Wps&&f.Kind==FindingKind.Registry&&f.Reference?.StartsWith(Marker,StringComparison.Ordinal)==true;
    internal static void Add(DeviceInfo device,ProductScanPlan plan,List<Finding> findings,List<string> warnings,Func<bool> more,ScanResult? previous=null)
    {
        var office=OfficeRecovery.Read(device).Associations;
        var cache=new Dictionary<string,(bool Wps,bool Office)>(StringComparer.OrdinalIgnoreCase);
        (bool Wps,bool Office) Identity(string path)
        {
            if(cache.TryGetValue(path,out var result))return result;
            try
            {
                // Inspect only candidate product paths. No network revocation check per file.
                bool wpsPath=VendorPath(path);
                if(!wpsPath&&!path.Contains("Microsoft Office",StringComparison.OrdinalIgnoreCase))return (false,false);
                var binary=new BinaryInspector().Read(path,false);
                result=(SafetyRules.Identify(binary)==Product.Wps,MicrosoftOffice(binary));
            }
            catch(Exception ex)when(ex is FileNotFoundException or DirectoryNotFoundException)
            {result=(VendorPath(path),false);}
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or CryptographicException or System.ComponentModel.Win32Exception){result=(false,false);}
            cache[path]=result;return result;
        }
        foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32})
        {
            if(!more())return;
            try
            {
                using var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,view);
                using var classes=machine.OpenSubKey(@"Software\Classes");if(classes==null)continue;
                Read(classes,machine,classes,"Machine|"+view+@"|Software\Classes\","Machine|"+view+"|",null,findings,office,Identity,more,previous);
            }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {warnings.Add("Abrir y vista previa del equipo: "+ErrorDetails.Message(ex));}
        }
        foreach(var profile in plan.Profiles??[new(device.UserSid,device.ProfilePath)])
        {
            if(!more())return;
            try
            {
                using var settings=UserProfiles.Open(profile);using var classes=UserProfiles.OpenClasses(profile);if(classes==null)continue;
                using var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64);
                using var machineClasses=machine.OpenSubKey(@"Software\Classes");if(machineClasses==null)continue;
                Read(classes,settings,machineClasses,"UserClasses|"+profile.Sid+"|","User|"+profile.Sid+"|",profile,findings,office,Identity,more,previous);
            }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {warnings.Add("Abrir y vista previa de "+profile.Path+": "+ErrorDetails.Message(ex));}
        }
    }
    private static void Read(RegistryKey classes,RegistryKey settings,RegistryKey machineClasses,string classPrefix,string settingsPrefix,UserProfile? profile,
        List<Finding> findings,IReadOnlyList<OfficeAssociation> office,Func<string,(bool Wps,bool Office)> identity,Func<bool> more,ScanResult? previous)
    {
        var classTree=new Tree(classes,profile);
        var edits=ExplorerRepair.Plan(classTree,new Tree(settings,profile),ReferenceEquals(classes,machineClasses)?classTree:new Tree(machineClasses),p=>identity(p).Wps,p=>identity(p).Office,office,more);
        foreach(var edit in edits)
        {
            using var key=(edit.Classes?classes:settings).OpenSubKey(edit.Key);if(key==null)continue;
            var location=(edit.Classes?classPrefix:settingsPrefix)+edit.Key+"|"+edit.Name;
            var content=RegistryResidues.SnapshotValue(key,edit.Name);
            if(!MatchesSnapshot(content,edit.Expected,profile))throw new IOException("La asociación cambió durante el análisis: "+location);
            var bound=edit with{Expected=SnapshotString(content)!};
            findings.Add(new(Product.Wps,FindingKind.Registry,"WPS en Abrir / vista previa",location,Trust.Confirmed,
                edit.Replacement!=null?"Restaura la referencia de Microsoft Office comprobada.":"Quita solo esta referencia de WPS; conserva documentos y las opciones de otras aplicaciones.",
                Reference:Marker+JsonSerializer.Serialize(bound),ContentHash:RegistryResidues.Hash(content)));
        }
        foreach(var prior in previous?.Findings.Where(IsFinding)??[])
        {
            if(!more())return;
            var edit=JsonSerializer.Deserialize<ExplorerEdit>(prior.Reference![Marker.Length..]);if(edit==null||!Allowed(edit))continue;
            var location=(edit.Classes?classPrefix:settingsPrefix)+edit.Key+"|"+edit.Name;
            if(location!=prior.Location||findings.Any(f=>f.Location==location))continue;
            using var key=(edit.Classes?classes:settings).OpenSubKey(edit.Key);
            if(key==null||!key.GetValueNames().Contains(edit.Name,StringComparer.Ordinal))continue;
            var content=RegistryResidues.SnapshotValue(key,edit.Name);
            if(CanReuse(prior,location,content))findings.Add(prior);
        }
    }
    internal static bool VendorPath(string path)
    {
        if(!SafetyRules.IsLocalPath(path))return false;
        var parts=Path.GetFullPath(path).Split('\\');
        if(!parts.Any(p=>new[]{"Kingsoft","WPS Office"}.Contains(p,StringComparer.OrdinalIgnoreCase)))return false;
        var name=Path.GetFileName(path);
        return new[]{"wps.exe","et.exe","wpp.exe","wpspdf.exe"}.Contains(name,StringComparer.OrdinalIgnoreCase)
            ||Path.GetExtension(path).Equals(".dll",StringComparison.OrdinalIgnoreCase)&&parts.Any(p=>p.Equals("office6",StringComparison.OrdinalIgnoreCase));
    }
    private static bool MicrosoftOffice(BinaryIdentity binary)=>binary.SignatureValid&&binary.Signer.Equals("Microsoft Corporation",StringComparison.OrdinalIgnoreCase)
        &&binary.ProductName.Contains("Office",StringComparison.OrdinalIgnoreCase);
    internal static void Clean(Finding finding,DeviceInfo device,SecureWorkspace workspace)
    {
        var edit=JsonSerializer.Deserialize<ExplorerEdit>(finding.Reference![Marker.Length..])??throw new IOException("Cambio de Explorer no válido.");
        var parts=finding.Location.Split('|',4);
        if(parts.Length!=4||finding.ContentHash==null||!Allowed(edit)||parts[3]!=edit.Name
            ||parts[2]!=(edit.Classes&&parts[0]=="Machine"?@"Software\Classes\":"")+edit.Key)throw new IOException("Referencia fuera del alcance.");
        using var hive=RegistryResidues.Open(parts,device,true);
        using var key=hive.OpenSubKey(parts[2],true);if(key==null||!key.GetValueNames().Contains(edit.Name,StringComparer.Ordinal))return;
        var content=RegistryResidues.SnapshotValue(key,edit.Name);
        if(RegistryResidues.Hash(content)!=finding.ContentHash||!MatchesSnapshot(content,edit.Expected))throw new IOException("La referencia cambió. Vuelve a analizar.");
        if(edit.Replacement!=null&&!edit.Key.EndsWith(@"\OpenWithList",StringComparison.OrdinalIgnoreCase))
        {
            using var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,parts[0]=="Machine"&&parts[1]=="Registry32"?RegistryView.Registry32:RegistryView.Registry64);
            using var cls=machine.OpenSubKey(@"Software\Classes")??throw new IOException("No se pudo comprobar Office.");
            string? target;
            if(edit.Key.EndsWith(ExplorerRepair.Preview,StringComparison.OrdinalIgnoreCase))
            {using var server=cls.OpenSubKey(@"CLSID\"+edit.Replacement+@"\InprocServer32");target=ExplorerRepair.Dll(server?.GetValue("") as string);}
            else target=PathSafety.ExecutableFromCommand(edit.Replacement);
            if(target==null||!MicrosoftOffice(new BinaryInspector().Read(target,false)))throw new IOException("El componente de Office ya no está comprobado.");
        }
        var backup=Path.Combine(workspace.BackupDirectory,Guid.NewGuid().ToString("N")+".registry.json");
        using(var output=new FileStream(backup,FileMode.CreateNew,FileAccess.Write,FileShare.None))
        {output.Write(JsonSerializer.SerializeToUtf8Bytes(new{finding.Location,Before=JsonSerializer.Deserialize<JsonElement>(content),edit.Replacement}));output.Flush(true);}
        if(RegistryResidues.Hash(RegistryResidues.SnapshotValue(key,edit.Name))!=finding.ContentHash)throw new IOException("La referencia cambió durante el respaldo.");
        if(edit.Replacement==null)key.DeleteValue(edit.Name,false);
        else key.SetValue(edit.Name,edit.Replacement,RegistryValueKind.String);
        key.Flush();
        bool verified=edit.Replacement==null?!key.GetValueNames().Contains(edit.Name,StringComparer.Ordinal):Equals(key.GetValue(edit.Name),edit.Replacement);
        if(!verified)throw new IOException("No se pudo confirmar la reparación de Explorer.");
        bool previewMissing=edit.Key.EndsWith(ExplorerRepair.Preview,StringComparison.OrdinalIgnoreCase)&&edit.Replacement==null;
        workspace.Log(Product.Wps,"Reparar Abrir / vista previa",finding.Location,previewMissing?"Pendiente":"Reparado",
            (previewMissing?"Se quitó WPS; falta un controlador de Office comprobado. Repara Microsoft Office para recuperar la vista previa. ":"Referencia de WPS corregida. ")+"Respaldo: "+backup);
        SHChangeNotify(0x08000000,0,IntPtr.Zero,IntPtr.Zero); // Refresh associations without restarting Explorer or the session.
    }
    internal static bool Allowed(ExplorerEdit edit)
    {
        if(edit.Key.Contains("UserChoice",StringComparison.OrdinalIgnoreCase)||edit.Key.Contains("..")||edit.Key.Contains('|')||edit.Name.Contains('|'))return false;
        if(!edit.Classes)return edit.Key==ExplorerRepair.PreviewList&&Guid.TryParseExact(edit.Name,"B",out _)&&edit.Replacement==null
            ||edit.Key.StartsWith(ExplorerRepair.FileExts+@"\.",StringComparison.OrdinalIgnoreCase)
                &&(edit.Key.EndsWith(@"\OpenWithProgids",StringComparison.OrdinalIgnoreCase)&&edit.Replacement==null
                    ||edit.Key.EndsWith(@"\OpenWithList",StringComparison.OrdinalIgnoreCase)&&(edit.Replacement==null||edit.Name=="MRUList"));
        return edit.Name==""&&(edit.Key.EndsWith(@"\shell\open\command",StringComparison.OrdinalIgnoreCase)
                ||edit.Key.EndsWith(@"\shell\edit\command",StringComparison.OrdinalIgnoreCase)
                ||edit.Key.EndsWith(@"\shellex\"+ExplorerRepair.Preview,StringComparison.OrdinalIgnoreCase)
                ||edit.Key.StartsWith('.')&&!edit.Key.Contains('\\')&&edit.Replacement==null)
            ||edit.Key.StartsWith('.')&&edit.Key.EndsWith(@"\OpenWithProgids",StringComparison.OrdinalIgnoreCase)&&edit.Replacement==null;
    }
    private sealed class Tree(RegistryKey root,UserProfile? profile=null):IExplorerTree
    {
        public string? Read(string path,string name="")
        {
            using var key=root.OpenSubKey(path);var value=key?.GetValue(name,null,RegistryValueOptions.DoNotExpandEnvironmentNames);
            return value is string s?(profile==null?s:UserProfiles.Expand(s,profile)):value is byte[] b&&b.Length==0?"":null;
        }
        public string[] Names(string path){using var key=root.OpenSubKey(path);return key?.GetValueNames()??[];}
        public string[] Children(string path){if(path=="")return root.GetSubKeyNames();using var key=root.OpenSubKey(path);return key?.GetSubKeyNames()??[];}
    }
    [DllImport("shell32.dll")]private static extern void SHChangeNotify(uint eventId,uint flags,IntPtr item1,IntPtr item2);
}
