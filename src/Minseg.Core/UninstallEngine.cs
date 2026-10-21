using Microsoft.Win32;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
namespace Minseg.Core;

public sealed class UninstallEngine
{
    private readonly BinaryInspector inspector=new();
    public async Task UninstallAsync(DeviceInfo device,ScanResult scan,IReadOnlySet<Product> selected,
        bool savedDocuments,bool alternateAccess,SecureWorkspace workspace,IProgress<string>? progress)
    {
        RequireConsent(scan,selected,savedDocuments,alternateAccess);
        var held=selected.Where(p=>workspace.RemovalSession.PendingReason(p)!=null).ToHashSet();
        foreach(var product in held)workspace.Log(product,"Desinstalar",product.Display(),"Pendiente",workspace.RemovalSession.PendingReason(product)!);
        bool anyDeskReady=true;
        if(selected.Contains(Product.AnyDesk)&&!held.Contains(Product.AnyDesk))
        {
            try{BackupAnyDeskEvidence(device,workspace);}
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException)
            {anyDeskReady=false;workspace.Log(Product.AnyDesk,"Desinstalar","AnyDesk","Pendiente","No se pudo guardar la evidencia: "+ErrorDetails.Message(ex));}
        }
        foreach(var original in InstalledPrograms.Deduplicate(scan.Installed).Where(a=>selected.Contains(a.Product)))
        {
            if(held.Contains(original.Product)||workspace.RemovalSession.PendingReason(original.Product)!=null)continue;
            if(original.Product==Product.AnyDesk&&!anyDeskReady)continue;
            progress?.Report("Desinstalando "+original.Name+"…");
            try
            {
                if(!original.MachineScope&&original.OwnerSid!=null&&original.OwnerSid!=device.UserSid)
                    throw new UnauthorizedAccessException("Instalación de otro usuario ("+original.OwnerSid+"). Debe desinstalarse desde esa sesión; no se ejecutará su archivo con otra cuenta.");
                var readWarnings=new List<string>();
                var current=InstalledPrograms.Revalidate(original,InstalledPrograms.Read(device,readWarnings));
                if(readWarnings.Count>0)throw new IOException("No se pudo volver a comprobar el registro. Escanea otra vez antes de desinstalar.");
                if(current==null) { workspace.Log(original.Product,"Desinstalar",original.Name,"Ya no está","La entrada ya no existe.");continue; }
                if(!InstalledPrograms.SameInstallation(current,original)) throw new IOException("La instalación cambió. Vuelve a analizar.");
                if(current.MachineScope&&!device.Administrator)throw new UnauthorizedAccessException("Abre la aplicación como administrador para esta instalación.");
                if(!current.MachineScope&&device.Administrator)throw new UnauthorizedAccessException("Esta instalación pertenece al usuario. Desinstálala desde la ventana sin permisos de administrador.");
                if(!current.MachineScope&&!device.Operator.Equals(device.User,StringComparison.OrdinalIgnoreCase))
                    throw new UnauthorizedAccessException("Abre el programa desde la sesión del usuario que tiene esta instalación.");
                var executable=current.MsiCode==null?RegisteredUninstaller.Resolve(current.UninstallCommand):null;
                progress?.Report("Comprobando el desinstalador de "+current.Product.Display()+"…");
                using var lease=executable!=null?ExecutionLease.Acquire(executable,device.Administrator):null;
                var command=BuildCommand(current,executable);
                workspace.Log(current.Product,"Desinstalar",command.Executable,"Inicio","Se abre el desinstalador comprobado.");
                var result=await ProcessRunner.RunAsync(command,TimeSpan.FromMinutes(8),false,()=>lease?.Dispose());
                workspace.RemovalSession.Observe(current.Product,result);
                var remains=InstalledPrograms.Read(device,readWarnings).Any(a=>InstalledPrograms.SameRegistryEntry(a,current));
                var status=result.TimedOut?"Pendiente":result.ExitCode==3010?"Reinicio pendiente":result.ExitCode==0&&!remains&&readWarnings.Count==0?"Desinstalado":"Revisar";
                workspace.Log(current.Product,"Desinstalar",current.Name,status,
                    result.TimedOut?"El asistente sigue abierto. Completa sus pasos y vuelve a analizar.":readWarnings.Count>0?"No se pudo comprobar el registro después de desinstalar. Escanea de nuevo.":$"Salida: {result.ExitCode}. Entrada de instalación presente: {remains}. Comprueba los restos con un nuevo análisis.");
            }
            catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or InvalidOperationException)
            { workspace.Log(original.Product,"Desinstalar",original.Name,"Pendiente",ErrorDetails.Message(ex)); }
        }
    }

    public CommandSpec BuildCommand(InstalledApp app)=>BuildCommand(app,app.MsiCode==null?RegisteredUninstaller.Resolve(app.UninstallCommand):null);
    private CommandSpec BuildCommand(InstalledApp app,string? executable)
    {
        if(app.MsiCode!=null)
        {
            // MSI identity is read back from Windows Installer, not trusted from an arbitrary registry command.
            if(InstalledPrograms.Hint(MsiProperty(app.MsiCode,"ProductName"),MsiProperty(app.MsiCode,"Publisher"))!=app.Product)
                throw new IOException("Windows Installer no confirmó la identidad del producto.");
            return SafetyRules.MsiUninstall(app.MsiCode);
        }
        var path=executable??throw new IOException("No hay una ruta comprobada para el desinstalador.");
        var identity=inspector.Read(path,allowTrustNetwork:true);
        RegisteredUninstaller.RequireIdentity(identity,app.Product);
        if(DeviceInventory.IsAdministrator)
        {
            var folder=Path.GetDirectoryName(path)!;
            if(!SecureWorkspace.IsRestricted(folder)||!SecureWorkspace.IsRestricted(path))
                throw new UnauthorizedAccessException("La carpeta del desinstalador permite cambios de usuarios. No se ejecutará con permisos de administrador.");
        }
        // No registry-provided switches are reused. WPS keeps its vendor wizard; AnyDesk documents --remove.
        return new CommandSpec(path,app.Product==Product.AnyDesk?["--remove"]:[]);
    }

    public void Clean(DeviceInfo device,ScanResult scan,IReadOnlyList<Finding> chosen,bool savedDocuments,
        bool alternateAccess,SecureWorkspace workspace,IProgress<string>? progress)
    {
        var products=chosen.Select(f=>f.Product).ToHashSet();RequireConsent(scan,products,savedDocuments,alternateAccess);
        var registryWarnings=new List<string>();IReadOnlyList<UserProfile> profiles=device.Administrator?UserProfiles.Read(device,registryWarnings):[new(device.UserSid,device.ProfilePath)];var current=InstalledPrograms.ReadAll(device,profiles,registryWarnings);
        if(registryWarnings.Count>0)throw new IOException("No se pudo comprobar el registro antes de limpiar. Escanea otra vez.");
        if(products.Contains(Product.AnyDesk))BackupAnyDeskEvidence(device,workspace);
        var cleanedPersistence=new HashSet<Finding>();
        foreach(var finding in chosen.OrderBy(f=>ExplorerResidues.IsFinding(f)?-1:f.Kind==FindingKind.Directory?4:f.Kind==FindingKind.Registry?3:f.Kind==FindingKind.Binary?2:f.Kind==FindingKind.Residue?1:0).ThenByDescending(f=>f.Location.Length))
        {
            try
            {
                if(workspace.RemovalSession.PendingReason(finding.Product) is string pending)throw new IOException(pending);
                if(!scan.Findings.Contains(finding)||(finding.Identity==null&&finding.Kind!=FindingKind.Directory&&!KingsoftDataResources.IsFinding(finding)&&!ExplorerResidues.IsFinding(finding))||finding.Trust!=Trust.Confirmed)
                    throw new IOException("Este elemento requiere revisión manual.");
                if(current.Any(a=>a.Product==finding.Product))throw new IOException("Primero completa la desinstalación y vuelve a analizar.");
                if(!device.Administrator&&RemovalLaunch.RequiresAdministrator(finding,device))throw new UnauthorizedAccessException("Este resto necesita la continuación de administrador.");
                if(ExplorerResidues.IsFinding(finding)){ExplorerResidues.Clean(finding,device,workspace);continue;}
                if(KingsoftDataResources.IsFinding(finding))
                {
                    var root=finding.Reference![KingsoftDataResources.Marker.Length..];
                    var allowed=ProductScanPlan.Create(device,new HashSet<Product>{Product.Wps},[],profiles).PersonalPaths??[];
                    if(!allowed.Contains(root,StringComparer.OrdinalIgnoreCase))throw new IOException("KingsoftData fuera de los perfiles comprobados.");
                    if(finding.Kind==FindingKind.Directory)
                    {
                        bool removed=SafeFileCleaner.DeleteEmptyDirectory(finding.Location,root);
                        workspace.Log(Product.Wps,"Limpiar KingsoftData",finding.Location,removed?"Limpiada":"Conservada",removed?"Carpeta vacía eliminada.":"Contiene datos que se conservan.");
                    }
                    else
                    {
                        var saved=SafeFileCleaner.PreserveAndDeleteKingsoftResource(finding.Location,finding.ContentHash??throw new IOException("Falta la huella."),workspace.BackupDirectory,root);
                        workspace.Log(Product.Wps,"Limpiar KingsoftData",finding.Location,"Limpiado","Respaldo: "+saved);
                    }
                    continue;
                }
                if(finding.Kind==FindingKind.Directory)
                {
                    if(finding.Reference==null||!ResidualArtifacts.TechnicalSubtree(finding.Location,finding.Reference,finding.Product))throw new IOException("Carpeta no admitida.");
                    if(!Directory.Exists(finding.Location))continue;
                    bool removed=SafeFileCleaner.DeleteEmptyDirectory(finding.Location,finding.Reference);
                    workspace.Log(finding.Product,"Limpiar carpeta",finding.Location,removed?"Limpiada":"Conservada",removed?"Carpeta vacía eliminada.":"Contiene archivos que se conservan o requieren revisión.");continue;
                }
                if(finding.Kind==FindingKind.Registry)
                {
                    if(SafetyRules.Identify(finding.Identity!)!=finding.Product)throw new IOException("Identidad de configuración no comprobada.");
                    if(File.Exists(finding.Identity!.Path)&&inspector.Read(finding.Identity.Path).Sha256!=finding.Identity.Sha256)throw new IOException("El programa cambió.");
                    RegistryResidues.Clean(finding,device,workspace);continue;
                }
                if(finding.Kind==FindingKind.Shortcut)
                {
                    if(finding.ContentHash==null||SafetyRules.Identify(finding.Identity!)!=finding.Product||ResidualArtifacts.ShortcutTarget(finding.Location)!=finding.Reference||finding.Reference!=finding.Identity!.Path)throw new IOException("El acceso directo cambió o no está comprobado.");
                    var shortcutBackup=SafeFileCleaner.PreserveAndDelete(finding.Location,finding.ContentHash,workspace.BackupDirectory);
                    workspace.Log(finding.Product,"Limpiar acceso",finding.Location,"Limpiado","Respaldo: "+shortcutBackup);continue;
                }
                if(finding.Identity==null)throw new IOException("Falta la identidad del archivo.");
                if(finding.Kind is FindingKind.Service or FindingKind.Task or FindingKind.Startup)
                {PersistenceCleaner.Clean(finding,device,workspace);cleanedPersistence.Add(finding);continue;}
                if(finding.Kind==FindingKind.Residue)
                {
                    bool technical=finding.Reference?.StartsWith("technical|",StringComparison.Ordinal)==true&&ResidualArtifacts.TechnicalFile(finding.Location,finding.Reference[10..],finding.Product)&&SafetyRules.Identify(finding.Identity!)==finding.Product;
                    if((!technical&&!ResidueRules.Eligible(finding.Location,finding.Identity!,finding.Product))||finding.ContentHash==null)throw new IOException("Resto no comprobado.");
                    if(File.Exists(finding.Identity.Path)&&inspector.Read(finding.Identity.Path).Sha256!=finding.Identity.Sha256)throw new IOException("El programa cambió; analiza otra vez.");
                    var saved=SafeFileCleaner.PreserveAndDelete(finding.Location,finding.ContentHash,workspace.BackupDirectory);
                    workspace.Log(finding.Product,"Limpiar resto",finding.Location,"Limpiado","Respaldo: "+saved);continue;
                }
                if(finding.Kind!=FindingKind.Binary)throw new IOException("Elemento no compatible con la limpieza.");
                if(scan.Findings.Any(f=>f.Kind is FindingKind.Service or FindingKind.Task or FindingKind.Startup&&f.Identity?.Path==finding.Location&&!cleanedPersistence.Contains(f)))
                    throw new IOException("Limpia primero los inicios, tareas o servicios que apuntan a este archivo.");
                if(!SafetyRules.CanClean(finding.Identity,finding.Product))throw new IOException("El archivo está protegido o no está confirmado.");
                var now=inspector.Read(finding.Location);
                if(now.Sha256!=finding.Identity.Sha256||SafetyRules.Identify(now)!=finding.Product)throw new IOException("El archivo cambió. Vuelve a analizar.");
                progress?.Report("Limpiando "+finding.Name+"…");
                workspace.Log(finding.Product,"Limpiar",finding.Location,"Inicio","Respaldo antes de borrar.");
                var backup=SafeFileCleaner.PreserveAndDelete(finding.Location,now.Sha256,workspace.BackupDirectory);
                workspace.Log(finding.Product,"Limpiar",finding.Location,"Limpiado","Respaldo: "+backup);
            }
            catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or COMException)
            {workspace.Log(finding.Product,"Limpiar",finding.Location,"Pendiente",ErrorDetails.Message(ex));}
        }
    }

    public static void RequireConsent(ScanResult scan,IReadOnlySet<Product> selected,bool documents,bool access)
    {
        if(DateTimeOffset.Now-scan.CapturedAt>TimeSpan.FromMinutes(15))throw new InvalidOperationException("El análisis es antiguo. Analiza otra vez.");
        if(selected.Count==0)throw new InvalidOperationException("Selecciona WPS, AnyDesk o ambos.");
        if(selected.Contains(Product.Wps)&&!documents)throw new InvalidOperationException("Confirma que guardaste los documentos de WPS.");
        if(selected.Contains(Product.AnyDesk)&&!access)throw new InvalidOperationException("Confirma que tienes otro acceso al equipo.");
    }

    private static void BackupAnyDeskEvidence(DeviceInfo device,SecureWorkspace workspace)
    {
        var roots=new List<string>{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AnyDesk")};
        if(SafetyRules.IsLocalPath(device.ProfilePath))roots.Add(Path.Combine(device.ProfilePath,@"AppData\Roaming\AnyDesk"));
        foreach(var root in roots)
        {
            if(!Directory.Exists(root))continue;
            PathSafety.RequireNoReparse(root);
            var folders=new List<string>{root};
            folders.AddRange(Directory.EnumerateDirectories(root).Where(p=>Path.GetFileName(p).StartsWith("ad_",StringComparison.OrdinalIgnoreCase)&&PathSafety.IsSafeExistingPath(p)));
            foreach(var file in folders.SelectMany(Directory.EnumerateFiles))
            {
                if(!new[]{".trace",".conf",".log"}.Contains(Path.GetExtension(file),StringComparer.OrdinalIgnoreCase)&&!Path.GetFileName(file).Equals("connection_trace.txt",StringComparison.OrdinalIgnoreCase))continue;
                PathSafety.RequireNoReparse(file);
                using var source=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.ReadWrite);
                if(source.Length>100L*1024*1024)throw new IOException("Una evidencia de AnyDesk supera 100 MB. Resguárdala antes de continuar.");
                var destination=Path.Combine(workspace.BackupDirectory,Guid.NewGuid().ToString("N")+".evidence");
                using(var backup=new FileStream(destination,FileMode.CreateNew,FileAccess.Write,FileShare.None)){source.CopyTo(backup);backup.Flush(true);}
                workspace.Log(Product.AnyDesk,"Guardar evidencia",file,"Guardada",destination);
            }
        }
    }
    private static string MsiProperty(string code,string property)
    {
        var value=new StringBuilder(2048);uint size=2048;
        return MsiGetProductInfo(code,property,value,ref size)==0?value.ToString():"";
    }
    [DllImport("msi.dll",CharSet=CharSet.Unicode)]private static extern uint MsiGetProductInfo(string product,string property,StringBuilder value,ref uint size);
}
