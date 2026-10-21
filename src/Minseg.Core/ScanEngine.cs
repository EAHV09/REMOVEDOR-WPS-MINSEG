using System.Diagnostics;
using System.Security.Cryptography;
namespace Minseg.Core;

public sealed class ScanEngine
{
    private readonly BinaryInspector inspector=new();
    public async Task<ScanResult> ScanAsync(DeviceInfo device,bool deep,IProgress<string>? progress,CancellationToken cancellation,ScanResult? previous=null)
        => await Task.Run(()=>Scan(device,deep,progress,cancellation,previous),cancellation);
    public Task<ScanResult> ScanProductAsync(DeviceInfo device,IReadOnlySet<Product> selected,ProductScanPlan plan,IProgress<string>? progress,CancellationToken cancellation,ScanResult? previous=null)
        =>Task.Run(()=>Scan(device,false,progress,cancellation,previous,plan,selected),cancellation);

    private ScanResult Scan(DeviceInfo device,bool deep,IProgress<string>? progress,CancellationToken token,ScanResult? previous,ProductScanPlan? focused=null,IReadOnlySet<Product>? selected=null)
    {
        var warnings=new List<string>();var findings=new List<Finding>();
        var installed=focused?.Profiles!=null?InstalledPrograms.ReadAll(device,focused.Profiles,warnings):InstalledPrograms.Read(device,warnings);
        if(selected!=null)installed=installed.Where(a=>selected.Contains(a.Product)).ToArray();
        if(focused!=null)warnings.AddRange(focused.Warnings);
        foreach(var app in installed) findings.Add(new Finding(app.Product,FindingKind.Installation,app.Name,app.Location,Trust.Review,
            "Instalación registrada. El desinstalador se comprobará antes de abrirlo.",Reference:app.RegistryPath));
        var roots=new List<string>();
        if(focused!=null)roots.AddRange(focused.Roots);
        else if(deep) roots.AddRange(DriveInfo.GetDrives().Where(d=>d.IsReady&&d.DriveType==DriveType.Fixed).Select(d=>d.RootDirectory.FullName));
        else
        {
            roots.AddRange(new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)});
            if(SafetyRules.IsLocalPath(device.ProfilePath)) roots.AddRange(new[]{"AppData\\Local","AppData\\Roaming","Downloads","Desktop"}.Select(p=>Path.Combine(device.ProfilePath,p)));
            roots.AddRange(installed.Select(a=>a.Location));
        }
        var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);var watch=Stopwatch.StartNew();int count=0,denied=0;bool complete=true;
        var limit=focused!=null?TimeSpan.FromSeconds(45):deep?TimeSpan.FromMinutes(10):TimeSpan.FromMinutes(3);
        int fileLimit=focused!=null?25000:500000;
        bool ContinueFiles()
        {
            token.ThrowIfCancellationRequested();
            if(watch.Elapsed<limit&&count<fileLimit)return true;
            complete=false;return false;
        }
        foreach(var root in roots.Where(SafetyRules.IsLocalPath).Select(p=>Path.TrimEndingDirectorySeparator(Path.GetFullPath(p))).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var pending=new Stack<string>();pending.Push(root);
            while(pending.TryPop(out var folder))
            {
                token.ThrowIfCancellationRequested();
                if(watch.Elapsed>limit||count>=fileLimit) { complete=false;pending.Clear();break; }
                if(!seen.Add(folder)||SkipDirectory(folder)) continue;
                try
                {
                    if((File.GetAttributes(folder)&FileAttributes.ReparsePoint)!=0) continue;
                    foreach(var sub in Directory.EnumerateDirectories(folder)) {if(!ContinueFiles())break;pending.Push(sub);}
                    foreach(var path in Directory.EnumerateFiles(folder))
                    {
                        token.ThrowIfCancellationRequested();count++;
                        if(watch.Elapsed>limit||count>fileLimit){complete=false;break;}
                        if(count%500==0) progress?.Report($"Buscando… {count:N0} archivos revisados");
                        var extension=Path.GetExtension(path);
                        if(!extension.Equals(".exe",StringComparison.OrdinalIgnoreCase)&&!extension.Equals(".dll",StringComparison.OrdinalIgnoreCase)) continue;
                        Inspect(path,findings,selected);
                    }
                }
                catch(Exception ex)when(focused!=null&&ex is FileNotFoundException or DirectoryNotFoundException){ }
                catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { denied++; }
            }
            if(!complete) break;
        }
        if(denied>0) { warnings.Add($"{denied} carpetas no pudieron leerse. No se cambiaron permisos.");complete=false; }
        AddResidues(findings,ContinueFiles);
        // Keep this session's pre-uninstall inventory: vendor uninstallers can remove the signed anchor first.
        if(previous!=null)foreach(var residue in previous.Findings.Where(f=>f.Kind==FindingKind.Residue&&f.Trust==Trust.Confirmed&&f.ContentHash!=null&&(selected==null||selected.Contains(f.Product))))
        {
            try
            {
                if(!ContinueFiles())break;
                if(!File.Exists(residue.Location)||!PathSafety.IsSafeExistingPath(residue.Location))continue;
                using var input=File.OpenRead(residue.Location);
                if(input.Length<=100L*1024*1024&&Convert.ToHexString(SHA256.HashData(input))==residue.ContentHash)findings.Add(residue);
            }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException){ }
        }
        if(watch.Elapsed>=limit||count>=fileLimit) {complete=false;warnings.Add("Búsqueda parcial: se alcanzó el límite de tiempo o archivos. Puedes repetirla.");}
        try { PersistenceScanner.Add(device,findings,warnings,previous,token,selected,focused?.Roots);
            if(warnings.Count>0)complete=false; }
        catch(Exception ex) when(ex is System.Runtime.InteropServices.COMException or System.ComponentModel.Win32Exception or InvalidOperationException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or UnauthorizedAccessException or System.Security.SecurityException)
        { warnings.Add("No se pudieron revisar todos los inicios, servicios o tareas. "+ErrorDetails.Message(ex));complete=false; }
        if(focused!=null&&selected!=null){ResidualArtifacts.Add(device,focused,selected,findings,warnings,previous,token);if(warnings.Count>0)complete=false;}
        return new ScanResult(DateTimeOffset.Now,findings.DistinctBy(f=>(f.Kind,f.Location)).ToArray(),installed,warnings,complete,focused!=null?ProductScanPlan.Coverage:deep?"Discos fijos locales y persistencia; no incluye carpetas protegidas ni otros perfiles completos.":"Ubicaciones habituales y persistencia.",selected);
    }

    private static bool SkipDirectory(string path)
    {
        var name=Path.GetFileName(path.TrimEnd('\\'));
        if(new[]{"Windows","$Recycle.Bin","System Volume Information","MINSEG-Control",".git","node_modules",".nuget"}.Contains(name,StringComparer.OrdinalIgnoreCase)) return true;
        return SafetyRules.IsPersonalData(path);
    }

    private void Inspect(string path,List<Finding> findings,IReadOnlySet<Product>? selected=null)
    {
        try
        {
            if(!PathSafety.IsSafeExistingPath(path)) return;
            var version=FileVersionInfo.GetVersionInfo(path);
            var hint=InstalledPrograms.Hint((version.ProductName??"")+" "+(version.FileDescription??"")+" "+(version.OriginalFilename??""));
            if(hint==null&&Path.GetFileName(path).Contains("AnyDesk",StringComparison.OrdinalIgnoreCase)) hint=Product.AnyDesk;
            if(hint==null||selected!=null&&!selected.Contains(hint.Value)) return;
            var identity=inspector.Read(path);var confirmed=SafetyRules.Identify(identity);
            findings.Add(new Finding(confirmed??hint.Value,FindingKind.Binary,Path.GetFileName(path),path,
                SafetyRules.IsPersonalData(path)?Trust.Protected:confirmed!=null?Trust.Confirmed:Trust.Review,
                confirmed!=null?"Firma de Windows y producto comprobados.":"Coincidencia pendiente: no se borrará automáticamente.",identity));
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or System.Security.Cryptography.CryptographicException) { }
    }

    private static void AddResidues(List<Finding> findings,Func<bool> continueScan)
    {
        var anchors=findings.Where(f=>f.Trust==Trust.Confirmed&&f.Identity!=null).DistinctBy(f=>Path.GetDirectoryName(f.Location),StringComparer.OrdinalIgnoreCase).ToArray();
        foreach(var anchor in anchors)
        {
            var folder=Path.GetDirectoryName(anchor.Location)!;
            try
            {
                foreach(var file in Directory.EnumerateFiles(folder))
                {
                    if(!continueScan())return;
                    if(!ResidueRules.Eligible(file,anchor.Identity!,anchor.Product)||!PathSafety.IsSafeExistingPath(file))continue;
                    using var input=File.OpenRead(file);if(input.Length>100L*1024*1024)continue;
                    findings.Add(new Finding(anchor.Product,FindingKind.Residue,Path.GetFileName(file),file,Trust.Confirmed,
                        "Archivo técnico junto al programa comprobado. Se respalda antes de limpiar.",anchor.Identity,anchor.Location,Convert.ToHexString(SHA256.HashData(input))));
                }
            }
            catch(Exception ex) when(ex is IOException or UnauthorizedAccessException) { }
        }
    }
}
