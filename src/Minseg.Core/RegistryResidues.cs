using Microsoft.Win32;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace Minseg.Core;

internal static class RegistryResidues
{
    private static readonly string[] WpsKeys=[@"Software\Kingsoft\Office",@"Software\Kingsoft\Office6",@"Software\Kingsoft\WPS Office",@"Software\Kingsoft\WPSCloud",@"Software\Kingsoft\WPSDrive",@"Software\WPS",@"Software\Kingsoft"];
    private const string NamespaceRoot=@"Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace";
    private const string ClassRoot=@"Software\Classes\CLSID";
    internal static bool AllowedUserClass(string key)=>key.StartsWith("CLSID\\",StringComparison.OrdinalIgnoreCase)&&Guid.TryParseExact(key[6..],"B",out _);
    internal static bool AllowedNamespace(string key)
        =>new[]{NamespaceRoot,ClassRoot}.Any(root=>key.StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase)&&Guid.TryParseExact(key[(root.Length+1)..],"B",out _));
    internal static bool Allowed(Product product,string key)=>product==Product.Wps?(WpsKeys.Contains(key,StringComparer.OrdinalIgnoreCase)||AllowedNamespace(key)):key.Equals(@"Software\AnyDesk",StringComparison.OrdinalIgnoreCase);
    internal static bool AllowedRun(string key)=>new[]{@"Software\Microsoft\Windows\CurrentVersion\Run",@"Software\Microsoft\Windows\CurrentVersion\RunOnce",@"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",@"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"}.Contains(key,StringComparer.OrdinalIgnoreCase);
    internal static void Add(DeviceInfo device,ProductScanPlan plan,IReadOnlySet<Product> products,List<Finding> findings,IReadOnlyList<Finding> evidence,List<string> warnings,Func<bool> more)
    {
        foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32})
        {
            try{using var hive=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,view);Read(hive,"Machine|"+view+"|",products,findings,evidence,more);ReadRun(hive,"Machine|"+view+"|",null,products,findings,evidence,more);ReadNamespaces(hive,"Machine|"+view+"|",null,products,findings,evidence,more);}
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException){warnings.Add("Registro del equipo incompleto: "+ErrorDetails.Message(ex));}
        }
        foreach(var profile in plan.Profiles??[new(device.UserSid,device.ProfilePath)])
        {
            if(!more())break;
            try
            {
                using var hive=UserProfiles.Open(profile);Read(hive,"User|"+profile.Sid+"|",products,findings,evidence,more);ReadRun(hive,"User|"+profile.Sid+"|",profile,products,findings,evidence,more);
                using var classes=UserProfiles.OpenClasses(profile);
                ReadNamespaces(hive,"User|"+profile.Sid+"|",profile,products,findings,evidence,more,classes);
            }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException){warnings.Add("Restos del registro de "+profile.Path+": "+ErrorDetails.Message(ex));}
        }
    }
    private static void ReadNamespaces(RegistryKey hive,string prefix,UserProfile? profile,IReadOnlySet<Product> products,List<Finding> findings,IReadOnlyList<Finding> evidence,Func<bool> more,RegistryKey? userClasses=null)
    {
        if(!products.Contains(Product.Wps))return;
        string classRoot=userClasses==null?ClassRoot:"CLSID";string classPrefix=userClasses==null?prefix:"UserClasses|"+profile!.Sid+"|";
        using var root=hive.OpenSubKey(NamespaceRoot);using var classes=(userClasses??hive).OpenSubKey(classRoot);
        var ids=(root?.GetSubKeyNames()??[]).Concat(classes?.GetSubKeyNames()??[]).Distinct(StringComparer.OrdinalIgnoreCase);
        foreach(var id in ids)
        {
            if(!more())return;
            if(!Guid.TryParseExact(id,"B",out _))continue;
            using var link=root?.OpenSubKey(id);using var cls=classes?.OpenSubKey(id);
            if(link==null&&cls==null)continue;
            var label=(link?.GetValue("") as string??"")+" "+(cls?.GetValue("") as string??"");
            using var server=cls?.OpenSubKey("InprocServer32");
            var target=server?.GetValue("",null,RegistryValueOptions.DoNotExpandEnvironmentNames) as string??"";
            if(profile!=null)target=UserProfiles.Expand(target,profile);
            target=target.Trim().Trim('"');
            bool candidate=(label+" "+target).Contains("wps",StringComparison.OrdinalIgnoreCase)||(label+" "+target).Contains("kingsoft",StringComparison.OrdinalIgnoreCase);
            if(!candidate&&!evidence.Any(f=>f.Kind==FindingKind.Registry&&(f.Location==prefix+NamespaceRoot+"\\"+id||f.Location==classPrefix+classRoot+"\\"+id)))continue;
            BinaryIdentity? identity=null;
            if(SafetyRules.IsLocalPath(target))
            {
                try{identity=new BinaryInspector().Read(target);}
                catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or CryptographicException){ }
            }
            foreach(var (location,key) in new[]{(prefix+NamespaceRoot+"\\"+id,link),(classPrefix+classRoot+"\\"+id,cls)})
            {
                if(key==null||!more())continue;
                var hash=Hash(Snapshot(key));
                var proof=identity;var reference="namespace|"+target;
                if(proof==null)
                {
                    var prior=evidence.FirstOrDefault(f=>f.Kind==FindingKind.Registry&&f.Location==location&&f.ContentHash==hash&&f.Reference?.StartsWith("namespace|",StringComparison.Ordinal)==true
                        &&(target.Length==0||f.Reference==reference));
                    if(prior!=null){proof=prior.Identity;reference=prior.Reference!;}
                }
                bool valid=proof!=null&&SafetyRules.Identify(proof)==Product.Wps;
                findings.Add(new(Product.Wps,FindingKind.Registry,"WPSDrive en el Explorador",location,valid?Trust.Confirmed:Trust.Review,
                    valid?"Extensión del Explorador vinculada a una biblioteca WPS comprobada.":"Entrada del Explorador por revisar: falta comprobar su biblioteca.",proof,reference,hash));
            }
        }
    }
    private static void ReadRun(RegistryKey hive,string prefix,UserProfile? profile,IReadOnlySet<Product> products,List<Finding> findings,IReadOnlyList<Finding> evidence,Func<bool> more)
    {
        foreach(var path in new[]{@"Software\Microsoft\Windows\CurrentVersion\Run",@"Software\Microsoft\Windows\CurrentVersion\RunOnce",@"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",@"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"})
        {
            using var key=hive.OpenSubKey(path);if(key==null)continue;
            foreach(var name in key.GetValueNames())
            {
                if(!more())return;
                var raw=key.GetValue(name,null,RegistryValueOptions.DoNotExpandEnvironmentNames) as string;if(raw==null)continue;
                var command=profile==null?raw:UserProfiles.Expand(raw,profile);
                var hint=PersistenceTarget.Classify(name,command,null);if(hint==null||!products.Contains(hint.Product))continue;
                var target=PathSafety.ExecutableFromCommand(command);
                if(PersistenceTarget.ContextDependent(command)||target==null)
                {
                    findings.Add(new(hint.Product,FindingKind.Registry,name,prefix+path+"|"+name,Trust.Review,"Inicio pendiente: no se pudo resolver el destino en el contexto de su usuario.",Reference:raw));continue;
                }
                BinaryIdentity? identity=null;var hash=Hash(SnapshotValue(key,name));var location=prefix+path+"|"+name;
                try{identity=new BinaryInspector().Read(target);}
                catch(Exception ex)when(ex is FileNotFoundException or DirectoryNotFoundException)
                {identity=evidence.FirstOrDefault(f=>f.Kind==FindingKind.Registry&&f.Location==location&&f.ContentHash==hash&&f.Reference==raw)?.Identity;}
                catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or CryptographicException){ }
                bool valid=identity!=null&&SafetyRules.Identify(identity)==hint.Product;
                findings.Add(new(hint.Product,FindingKind.Registry,name,location,valid?Trust.Confirmed:Trust.Review,"Inicio del registro del perfil; solo se elimina el valor comprobado.",identity,raw,hash));
            }
        }
    }
    internal static string SnapshotValue(RegistryKey key,string name)=>JsonSerializer.Serialize(new{Name=name,Kind=key.GetValueKind(name).ToString(),Value=key.GetValue(name,null,RegistryValueOptions.DoNotExpandEnvironmentNames)});
    private static void Read(RegistryKey hive,string prefix,IReadOnlySet<Product> products,List<Finding> findings,IReadOnlyList<Finding> evidence,Func<bool> more)
    {
        foreach(var product in products)
        {
            var anchor=evidence.FirstOrDefault(f=>f.Product==product&&SafetyRules.Identify(f.Identity!)==product)?.Identity;
            foreach(var path in product==Product.Wps?WpsKeys:[@"Software\AnyDesk"])
            {
                if(!more())return;
                using var key=hive.OpenSubKey(path);if(key==null)continue;
                bool empty=key.SubKeyCount==0&&key.ValueCount==0;
                bool container=path.Equals(@"Software\Kingsoft",StringComparison.OrdinalIgnoreCase);
                var content=Snapshot(key);
                findings.Add(new(product,FindingKind.Registry,path,prefix+path,anchor!=null&&(!container||empty)?Trust.Confirmed:Trust.Review,
                    container&&!empty?"Contenedor Kingsoft: se conserva mientras tenga otras claves o valores.":"Configuración del producto; se respalda antes de limpiar.",anchor,ContentHash:Hash(content)));
            }
        }
    }
    internal static void Clean(Finding finding,DeviceInfo device,SecureWorkspace workspace)
    {
        var parts=finding.Location.Split('|',4);
        bool value=parts.Length==4&&AllowedRun(parts[2]);
        bool allowedClass=parts.Length==3&&parts[0]=="UserClasses"&&finding.Product==Product.Wps&&AllowedUserClass(parts[2]);
        if((parts.Length!=3&&!value)||(!value&&!allowedClass&&!Allowed(finding.Product,parts[2]))||finding.ContentHash==null)throw new IOException("Clave no admitida.");
        using var hive=Open(parts,device,true);
        using(var key=hive.OpenSubKey(parts[2],value))
        {
            if(key==null)return;
            if(value&&!key.GetValueNames().Contains(parts[3],StringComparer.Ordinal))return;
            if(parts[2].Equals(@"Software\Kingsoft",StringComparison.OrdinalIgnoreCase)&&(key.ValueCount>0||key.SubKeyCount>0))throw new IOException("Kingsoft aún contiene otras claves: se conserva.");
            var content=value?SnapshotValue(key,parts[3]):Snapshot(key);if(Hash(content)!=finding.ContentHash)throw new IOException("La configuración cambió. Se conserva.");
            var backup=Path.Combine(workspace.BackupDirectory,Guid.NewGuid().ToString("N")+".registry.json");
            using(var output=new FileStream(backup,FileMode.CreateNew,FileAccess.Write,FileShare.None))
            using(var document=JsonDocument.Parse(content))
            {var bytes=JsonSerializer.SerializeToUtf8Bytes(new{Location=finding.Location,Data=document.RootElement});output.Write(bytes);output.Flush(true);}
            // Recheck after backup, then remove only this exact product subtree. Never delete Software or a loaded hive.
            if(Hash(value?SnapshotValue(key,parts[3]):Snapshot(key))!=finding.ContentHash)throw new IOException("La configuración cambió durante el respaldo. Se conserva.");
            if(value)key.DeleteValue(parts[3],false);else hive.DeleteSubKeyTree(parts[2],false);
            workspace.Log(finding.Product,"Limpiar registro",finding.Location,"Limpiado","Respaldo: "+backup);
        }
    }
    internal static RegistryKey Open(string[] parts,DeviceInfo device,bool writable)
    {
        if(parts[0]=="Machine"&&Enum.TryParse<RegistryView>(parts[1],out var view)&&view is RegistryView.Registry32 or RegistryView.Registry64)
            return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,view);
        if(parts[0] is not ("User" or "UserClasses"))throw new IOException("Registro no admitido.");
        var warnings=new List<string>();var profile=UserProfiles.Read(device,warnings).SingleOrDefault(p=>p.Sid==parts[1])??throw new IOException("El perfil ya no está registrado.");
        return parts[0]=="UserClasses"?UserProfiles.OpenClasses(profile,writable)??throw new IOException("Clases del perfil no accesibles."):UserProfiles.Open(profile,writable);
    }
    internal static string Hash(string value)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    internal static string Snapshot(RegistryKey key)
    {
        int count=0;var entries=new List<object>();
        void Read(RegistryKey current,string path,int depth)
        {
            if(depth>16||++count>2048)throw new IOException("Registro demasiado grande para respaldar en esta pasada.");
            var values=new List<object>();
            foreach(var name in current.GetValueNames().Order(StringComparer.Ordinal))
            {
                var value=current.GetValue(name,null,RegistryValueOptions.DoNotExpandEnvironmentNames);
                values.Add(new{Name=name,Kind=current.GetValueKind(name).ToString(),Value=value});
                if(++count>2048)throw new IOException("Demasiados valores del registro.");
            }
            entries.Add(new{Path=path,Values=values});
            foreach(var name in current.GetSubKeyNames().Order(StringComparer.Ordinal))
            {using var child=current.OpenSubKey(name)??throw new IOException("Clave no accesible.");Read(child,path+"\\"+name,depth+1);}
        }
        Read(key,"",0);var content=JsonSerializer.Serialize(entries);if(content.Length>1024*1024)throw new IOException("Respaldo de registro demasiado grande.");return content;
    }
}
