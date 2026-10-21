using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
namespace Minseg.Core;

public sealed record PolicyState(string Status,string Detail,bool? Audit=null);
public sealed record PolicyRecord(bool Audit,string BinaryHash,DateTimeOffset Applied,string BinaryPath,string Version,string XmlPath,string XmlHash);
public sealed class PolicyService
{
    private static string CiTool=>Path.Combine(Environment.SystemDirectory,"CiTool.exe");
    private static string PolicyRoot=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"MINSEG-Control");
    // Keep managing the existing AppLocker policy after a Windows upgrade adds CiTool.
    private static bool UseAppLocker=>File.Exists(Path.Combine(PolicyRoot,"applocker-state.json"))||!File.Exists(CiTool);
    private static string ActivePath=>Path.Combine(Environment.SystemDirectory,@"CodeIntegrity\CiPolicies\Active",PolicyBuilder.PolicyId+".cip");

    public async Task<PolicyState> ReadAsync()
    {
        if(UseAppLocker)return await new AppLockerService().ReadAsync();
        var marker=Path.Combine(PolicyRoot,"policy-state.json");
        if(!File.Exists(marker))return File.Exists(CiTool)?new("Sin aplicar","Aún no hay una política creada por esta herramienta."):
            new("Bloqueo no disponible aquí","El bloqueo integrado necesita Windows 11 22H2 o posterior con CiTool y ConfigCI. En este equipo puedes buscar, desinstalar y limpiar. TI debe aplicar un bloqueo compatible desde su administración empresarial.");
        try
        {
            PathSafety.RequireNoReparse(marker);
            if(!SecureWorkspace.IsRestricted(PolicyRoot)||!SecureWorkspace.IsRestricted(marker))return new("No comprobado","El registro del bloqueo tiene permisos inseguros.");
            if(new FileInfo(marker).Length>8192)return new("No comprobado","Registro de bloqueo inválido.");
            var record=JsonSerializer.Deserialize<PolicyRecord>(File.ReadAllText(marker))??throw new IOException("Registro inválido.");
            if(!File.Exists(ActivePath))return new("No activo","Windows no tiene el archivo de esta política.");
            PathSafety.RequireNoReparse(ActivePath);
            using(var file=File.OpenRead(ActivePath))if(Convert.ToHexString(SHA256.HashData(file))!=record.BinaryHash)return new("Cambió","La política instalada no coincide con el registro.");
            if(!File.Exists(CiTool))return new("Por comprobar tras reinicio","Política instalada. Windows no ofrece CiTool para comprobar la carga en esta versión.",record.Audit);
            var result=await ProcessRunner.RunAsync(new(CiTool,["--list-policies","--json"]),TimeSpan.FromSeconds(20));
            if(result.ExitCode!=0)return new("No comprobado","Abre como administrador para consultar el estado de Windows.",record.Audit);
            return PolicyStatus.Parse(result.Output,record.Audit,record.Version);
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or JsonException or System.ComponentModel.Win32Exception)
        {return new("No comprobado",ErrorDetails.Message(ex));}
    }

    public async Task<PolicyState> ApplyAsync(bool audit,ScanResult? scan,bool documentsSaved,bool alternateAccess,SecureWorkspace workspace,bool checkedCompatibility=false)
    {
        if(UseAppLocker)return await new AppLockerService().ApplyAsync(audit,documentsSaved,alternateAccess,workspace,checkedCompatibility);
        if(!DeviceInventory.IsAdministrator)throw new UnauthorizedAccessException("Abre como administrador para cambiar el bloqueo.");
        if(!documentsSaved||!alternateAccess)throw new InvalidOperationException("Confirma que guardaste tus documentos y tienes otro acceso al equipo.");
        if(!File.Exists(CiTool))throw new InvalidOperationException("El bloqueo comprobado necesita CiTool de Windows 11 22H2 o posterior. En esta versión puedes analizar y desinstalar; TI debe aplicar el control empresarial compatible.");
        if(!audit)PolicyStatus.RequireAudit(await ReadAsync(),checkedCompatibility);
        var ps=Path.Combine(Environment.SystemDirectory,@"WindowsPowerShell\v1.0\powershell.exe");
        if(!File.Exists(Path.Combine(Environment.SystemDirectory,@"WindowsPowerShell\v1.0\Modules\ConfigCI\ConfigCI.psd1")))
            throw new InvalidOperationException("Esta edición de Windows no incluye el generador de políticas. El bloqueo no se aplicó.");
        var folder=Path.Combine(workspace.SessionDirectory,"politica-"+Guid.NewGuid().ToString("N"));SecureWorkspace.EnsurePrivateDirectory(folder,true);
        string xml=Path.Combine(folder,"MINSEG.xml"),cip=Path.Combine(folder,"MINSEG.cip"),script=Path.Combine(folder,"BuildPolicy.ps1"),samplesPath=Path.Combine(folder,"muestras.json");
        var timestamp=(ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var document=audit?PolicyBuilder.Create(true,timestamp):PolicyBuilder.Promote(ReadAuditedXml(),timestamp);
        var version=document.Root!.Element(PolicyBuilder.Namespace+"VersionEx")!.Value;document.Save(xml);
        using(var resource=Assembly.GetExecutingAssembly().GetManifestResourceStream("Minseg.Core.BuildPolicy.ps1")!)
        using(var output=new FileStream(script,FileMode.CreateNew,FileAccess.Write))resource.CopyTo(output);
        var samples=new List<object>();long bytes=0;
        if(audit&&scan!=null&&DateTimeOffset.Now-scan.CapturedAt<TimeSpan.FromMinutes(15))
        foreach(var item in scan.Findings.Where(f=>f.Kind==FindingKind.Binary&&f.Trust==Trust.Confirmed&&f.Identity!=null).DistinctBy(f=>f.Identity!.Sha256).Take(64))
        {
            if(!File.Exists(item.Location)||bytes+item.Identity!.Length>256L*1024*1024)continue;
            try
            {
                var identity=new BinaryInspector().Read(item.Location);
                if(identity.Sha256!=item.Identity.Sha256||SafetyRules.Identify(identity)!=item.Product)continue;
                var copy=Path.Combine(folder,"muestra-"+samples.Count+Path.GetExtension(item.Location));
                File.Copy(item.Location,copy,false);
                using(var input=File.OpenRead(copy))if(Convert.ToHexString(SHA256.HashData(input))!=identity.Sha256)throw new IOException("Muestra modificada.");
                samples.Add(new{Path=copy,identity.Sha256});bytes+=identity.Length;
            }
            catch(IOException){workspace.Log(item.Product,"Preparar bloqueo",item.Location,"Pendiente","No se pudo guardar esta muestra.");}
        }
        File.WriteAllText(samplesPath,JsonSerializer.Serialize(samples));
        workspace.Log(null,"Preparar bloqueo",xml,"Inicio",audit?"Auditoría: todavía permite ejecutar.":"Bloqueo de WPS y AnyDesk.");
        var compiled=await ProcessRunner.RunAsync(new(ps,["-NoProfile","-NonInteractive","-File",script,"-InputXml",xml,"-OutputCip",cip,"-SamplesJson",samplesPath]),TimeSpan.FromMinutes(3));
        if(compiled.ExitCode!=0||!File.Exists(cip))throw new IOException("No se pudo generar la política. Se respetó la configuración de PowerShell del equipo. Detalle: "+compiled.Error[..Math.Min(500,compiled.Error.Length)]);
        using(var reader=XmlReader.Create(xml,new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null}))PolicyBuilder.Validate(XDocument.Load(reader));
        if(File.Exists(ActivePath))
        {
            var existing=await ReadAsync();
            if(existing.Status is "Cambió" or "No comprobado" or "Sin aplicar")throw new IOException("Hay una política con el mismo identificador que no pudo validarse. Se conserva.");
            File.Copy(ActivePath,Path.Combine(folder,"anterior.cip"),false);
        }
        if(File.Exists(CiTool))
        {
            var applied=await ProcessRunner.RunAsync(new(CiTool,["--update-policy",cip,"--json"]),TimeSpan.FromSeconds(45));
            if(applied.ExitCode!=0)throw new IOException("Windows no confirmó que la política se aplicara. Vuelve a comprobar el estado.");
        }
        else
        {
            var activeDirectory=Path.GetDirectoryName(ActivePath)!;
            if(!Directory.Exists(activeDirectory))throw new IOException("Windows no tiene el almacén de políticas múltiples.");
            PathSafety.RequireNoReparse(activeDirectory);File.Copy(cip,ActivePath,true);
        }
        using var binary=File.OpenRead(cip);var hash=Convert.ToHexString(SHA256.HashData(binary));
        using var xmlFile=File.OpenRead(xml);var xmlHash=Convert.ToHexString(SHA256.HashData(xmlFile));
        File.WriteAllText(Path.Combine(PolicyRoot,"policy-state.json"),JsonSerializer.Serialize(new PolicyRecord(audit,hash,DateTimeOffset.Now,cip,version,xml,xmlHash)));
        var state=await ReadAsync();workspace.Log(null,"Aplicar bloqueo",PolicyBuilder.PolicyId,state.Status,state.Detail);return state;
    }

    private static XDocument ReadAuditedXml()
    {
        var marker=Path.Combine(PolicyRoot,"policy-state.json");PathSafety.RequireNoReparse(marker);
        var record=JsonSerializer.Deserialize<PolicyRecord>(File.ReadAllText(marker))??throw new IOException("No se encontró la política auditada.");
        if(!record.Audit||!SafetyRules.IsContained(PolicyRoot,record.XmlPath))throw new IOException("La política auditada no es válida.");
        PathSafety.RequireNoReparse(record.XmlPath);
        if(!SecureWorkspace.IsRestricted(record.XmlPath))throw new IOException("La política auditada tiene permisos inseguros.");
        using var source=new FileStream(record.XmlPath,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(source.Length>10L*1024*1024||Convert.ToHexString(SHA256.HashData(source))!=record.XmlHash)throw new IOException("La política auditada cambió. Prueba de nuevo en auditoría.");
        source.Position=0;using var reader=XmlReader.Create(source,new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null});
        return XDocument.Load(reader);
    }

    public async Task<PolicyState> RemoveAsync(SecureWorkspace workspace)
    {
        if(UseAppLocker)return await new AppLockerService().RemoveAsync(workspace);
        if(!DeviceInventory.IsAdministrator)throw new UnauthorizedAccessException("Abre como administrador para desactivar el bloqueo.");
        var state=await ReadAsync();
        if(state.Status is "No comprobado" or "Cambió" or "Sin aplicar")throw new IOException("La política no pudo validarse. No se modificó.");
        if(!File.Exists(CiTool))throw new IOException("Esta versión requiere que TI desactive la política con el procedimiento documentado.");
        var result=await ProcessRunner.RunAsync(new(CiTool,["--remove-policy",PolicyBuilder.PolicyId,"--json"]),TimeSpan.FromSeconds(45));
        if(result.ExitCode!=0)throw new IOException("Windows no confirmó la desactivación.");
        workspace.Log(null,"Desactivar bloqueo",PolicyBuilder.PolicyId,"Solicitado","Comprueba el estado; Windows puede pedir reinicio.");
        return await ReadAsync();
    }
}
