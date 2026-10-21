using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
namespace Minseg.Core;

internal static class ResidualArtifacts
{
    internal static IEnumerable<Finding> InstallationEvidence(IEnumerable<InstalledApp> apps,IReadOnlySet<Product> products)
    {
        var result=new List<Finding>();
        foreach(var app in apps.Where(a=>products.Contains(a.Product)&&a.MsiCode==null))
        {
            try
            {
                var identity=new BinaryInspector().Read(RegisteredUninstaller.Resolve(app.UninstallCommand));
                if(SafetyRules.Identify(identity)==app.Product)result.Add(new(app.Product,FindingKind.Binary,Path.GetFileName(identity.Path),identity.Path,Trust.Confirmed,"Desinstalador comprobado antes de actuar.",identity));
            }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or CryptographicException){ }
        }
        return result;
    }
    internal static void Add(DeviceInfo device,ProductScanPlan plan,IReadOnlySet<Product> products,List<Finding> findings,List<string> warnings,ScanResult? previous,CancellationToken token,bool snapshotOnly=false)
    {
        var watch=Stopwatch.StartNew();int count=0;
        bool More(){token.ThrowIfCancellationRequested();if(watch.Elapsed<TimeSpan.FromSeconds(20)&&++count<=25000)return true;if(!warnings.Contains("Restos y accesos: revisión parcial por límite de tiempo o archivos."))warnings.Add("Restos y accesos: revisión parcial por límite de tiempo o archivos.");return false;}
        var evidence=findings.Concat(previous?.Findings??[]).Where(f=>f.Trust==Trust.Confirmed&&f.Identity!=null&&products.Contains(f.Product)).ToArray();
        foreach(var root in plan.Roots)
        {
            if(!More())break;
            var product=RootProduct(root);if(product==null||!products.Contains(product.Value))continue;
            var anchor=evidence.FirstOrDefault(f=>f.Product==product&&SafetyRules.Identify(f.Identity!)==product)?.Identity;
            var folders=new Stack<string>();folders.Push(root);
            while(folders.TryPop(out var folder))
            {
                if(!More())break;
                if(SafetyRules.IsPersonalData(folder)||!TechnicalSubtree(folder,root,product.Value))continue;
                try
                {
                    PathSafety.RequireNoReparse(folder);
                    var entries=Directory.EnumerateFileSystemEntries(folder).Take(25001).ToArray();
                    if(entries.Length>25000)warnings.Add("Carpeta con demasiados elementos; revisión parcial: "+folder);
                    bool sharedRoot=folder.Equals(root,StringComparison.OrdinalIgnoreCase)&&Path.GetFileName(root).Equals("Kingsoft",StringComparison.OrdinalIgnoreCase)
                        &&entries.Any(entry=>!TechnicalSubtree(entry,root,product.Value));
                    if(!snapshotOnly&&!sharedRoot)findings.Add(new(product.Value,FindingKind.Directory,Path.GetFileName(folder),folder,anchor!=null?Trust.Confirmed:Trust.Review,
                        "Solo se elimina si está vacía; no se borran carpetas en bloque.",anchor,Reference:root));
                    foreach(var entry in entries)
                    {
                        if(!More())break;
                        var attributes=File.GetAttributes(entry);
                        if((attributes&FileAttributes.ReparsePoint)!=0){if(!snapshotOnly)findings.Add(new(product.Value,FindingKind.PersonalData,Path.GetFileName(entry),entry,Trust.Protected,"Enlace o archivo de nube: conservado."));continue;}
                        if((attributes&FileAttributes.Directory)!=0){if(TechnicalSubtree(entry,root,product.Value))folders.Push(entry);continue;}
                        if(SafetyRules.IsPersonalData(entry)){if(!snapshotOnly)findings.Add(new(product.Value,FindingKind.PersonalData,Path.GetFileName(entry),entry,Trust.Protected,"Datos personales: conservados."));continue;}
                        if(anchor!=null&&TechnicalFile(entry,root,product.Value))
                        {
                            using var input=new FileStream(entry,FileMode.Open,FileAccess.Read,FileShare.Read);
                            if(input.Length>100L*1024*1024){warnings.Add("Resto técnico demasiado grande: "+entry);continue;}
                            findings.Add(new(product.Value,FindingKind.Residue,Path.GetFileName(entry),entry,Trust.Confirmed,"Resto técnico en una ruta del producto comprobado. Se respalda antes de borrar.",anchor,"technical|"+root,Convert.ToHexString(SHA256.HashData(input))));
                        }
                        else if(!snapshotOnly&&!findings.Any(f=>f.Location.Equals(entry,StringComparison.OrdinalIgnoreCase)))
                            findings.Add(new(product.Value,FindingKind.Residue,Path.GetFileName(entry),entry,Trust.Review,"Archivo sin identidad suficiente para borrarlo automáticamente."));
                    }
                }
                catch(Exception ex)when(ex is FileNotFoundException or DirectoryNotFoundException){ }
                catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException){warnings.Add("No se pudo revisar "+folder+": "+ErrorDetails.Message(ex));}
            }
        }
        foreach(var path in plan.PersonalPaths??[])
        {
            if(!More())break;
            if(products.Contains(Product.Wps)&&KingsoftDataResources.IsRoot(path))
            {if(!snapshotOnly)KingsoftDataResources.Add(path,findings,warnings,More);continue;}
            try{File.GetAttributes(path);if(products.Contains(Product.Wps)&&!snapshotOnly)findings.Add(new(Product.Wps,FindingKind.PersonalData,Path.GetFileName(path),path,Trust.Protected,"Carpeta de datos o nube: se conserva y se muestra en el informe."));}
            catch(Exception ex)when(ex is FileNotFoundException or DirectoryNotFoundException){ }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException){warnings.Add("No se pudo comprobar la carpeta de datos: "+path);}
        }
        foreach(var root in plan.ShortcutRoots??[])
        {
            var folders=new Stack<string>();folders.Push(root);
            while(folders.TryPop(out var folder))
            {
                if(!More())break;
                try
                {
                    PathSafety.RequireNoReparse(folder);
                    // Desktop: only loose shortcuts. Programs: include subfolders, bounded by the same budget.
                    if(root.EndsWith("Programs",StringComparison.OrdinalIgnoreCase))foreach(var child in Directory.EnumerateDirectories(folder))folders.Push(child);
                    foreach(var path in Directory.EnumerateFiles(folder,"*.lnk"))
                    {
                        if(!More())break;
                        AddShortcut(path,products,findings,previous,warnings);
                    }
                }
                catch(Exception ex)when(ex is FileNotFoundException or DirectoryNotFoundException){ }
                catch(Exception ex)when(ex is IOException or UnauthorizedAccessException){warnings.Add("Accesos directos no accesibles: "+folder);}
            }
        }
        if(products.Contains(Product.Wps))ExplorerResidues.Add(device,plan,findings,warnings,More,previous);
        RegistryResidues.Add(device,plan,products,findings,evidence,warnings,More);
    }
    internal static Product? RootProduct(string root)
    {
        var name=Path.GetFileName(Path.TrimEndingDirectorySeparator(root));
        if(new[]{"Kingsoft","WPS","WPS Office"}.Contains(name,StringComparer.OrdinalIgnoreCase))return Product.Wps;
        return name.Equals("AnyDesk",StringComparison.OrdinalIgnoreCase)?Product.AnyDesk:null;
    }
    internal static bool TechnicalFile(string path,string root,Product product)
    {
        if(!TechnicalSubtree(path,root,product)||!SafetyRules.IsContained(root,path)||SafetyRules.IsPersonalData(path))return false;
        return new[]{".log",".trace",".tmp",".cache",".conf",".ini",".cfg"}.Contains(Path.GetExtension(path),StringComparer.OrdinalIgnoreCase);
    }
    internal static bool TechnicalSubtree(string path,string root,Product product)
    {
        if(RootProduct(root)!=product)return false;
        if(Path.GetFullPath(path).Equals(Path.GetFullPath(root),StringComparison.OrdinalIgnoreCase))return true;
        if(!SafetyRules.IsContained(root,path))return false;
        if(product==Product.Wps&&Path.GetFileName(root).Equals("Kingsoft",StringComparison.OrdinalIgnoreCase))
        {
            var first=Path.GetRelativePath(root,path).Split('\\','/')[0];
            if(!new[]{"office6","WPS Office","WPS","WPSCloud"}.Contains(first,StringComparer.OrdinalIgnoreCase))return false;
        }
        return true;
    }
    private static void AddShortcut(string path,IReadOnlySet<Product> products,List<Finding> findings,ScanResult? previous,List<string> warnings)
    {
        try
        {
            PathSafety.RequireNoReparse(path);var target=ShortcutTarget(path);if(!SafetyRules.IsLocalPath(target))return;
            var hint=InstalledPrograms.Hint(Path.GetFileName(path)+" "+target);
            if(hint==null&&(path.Contains("kingsoft",StringComparison.OrdinalIgnoreCase)||path.Contains("wps",StringComparison.OrdinalIgnoreCase)))hint=Product.Wps;
            if(hint==null||!products.Contains(hint.Value))return;
            using var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            if(input.Length>1024*1024)throw new IOException("Acceso directo demasiado grande.");
            var hash=Convert.ToHexString(SHA256.HashData(input));BinaryIdentity? identity=null;
            try{identity=new BinaryInspector().Read(target);}
            catch(Exception ex)when(ex is FileNotFoundException or DirectoryNotFoundException)
            {identity=previous?.Findings.FirstOrDefault(f=>f.Kind==FindingKind.Shortcut&&f.Location.Equals(path,StringComparison.OrdinalIgnoreCase)&&f.ContentHash==hash&&f.Reference==target&&f.Trust==Trust.Confirmed)?.Identity;}
            var product=identity==null?null:SafetyRules.Identify(identity);
            findings.RemoveAll(f=>f.Location.Equals(path,StringComparison.OrdinalIgnoreCase));
            findings.Add(new(product??hint.Value,FindingKind.Shortcut,Path.GetFileName(path),path,product==hint?Trust.Confirmed:Trust.Review,
                product==hint?"Acceso directo con destino comprobado; no se borran los archivos de destino desde aquí.":"El nombre coincide, pero falta comprobar su destino.",identity,target,hash));
        }
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or COMException or CryptographicException){warnings.Add("Acceso directo pendiente: "+path+". "+ErrorDetails.Message(ex));}
    }
    internal static string ShortcutTarget(string path)
    {
        dynamic shell=Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")??throw new IOException("Lector de accesos no disponible."))!;
        object? link=null;
        try{dynamic shortcut=link=shell.CreateShortcut(path);return (string)shortcut.TargetPath;}
        finally{if(link!=null)Marshal.FinalReleaseComObject(link);Marshal.FinalReleaseComObject((object)shell);}
    }
}
