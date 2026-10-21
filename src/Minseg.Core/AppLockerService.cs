using Microsoft.Win32;
using System.Reflection;
using System.Text;
using System.Text.Json;
namespace Minseg.Core;

public sealed class AppLockerService
{
    private static string ModulePath=>Path.Combine(Environment.SystemDirectory,@"WindowsPowerShell\v1.0\Modules\AppLocker\AppLocker.psd1");
    private static string Root=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"MINSEG-Control");
    private static string Marker=>Path.Combine(Root,"applocker-state.json");

    private static void RequireSupport()
    {
        using var system=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64);
        using var key=system.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        int.TryParse(key?.GetValue("CurrentBuildNumber")?.ToString(),out var build);
        int.TryParse(key?.GetValue("UBR")?.ToString(),out var revision);
        if(!AppLockerPolicy.Supports(build,revision,key?.GetValue("EditionID") as string??"")||!File.Exists(ModulePath))
            throw new InvalidOperationException("Esta instalación de Windows necesita una versión compatible y actualizaciones para AppLocker. Windows 10 Enterprise/LTSC compatible o Windows 10 2004+ actualizado. No se aplicó bloqueo.");
    }
    public async Task<PolicyState> ReadAsync()
    {
        try
        {
            RequireSupport();
            if(!File.Exists(Marker))return new("Sin aplicar","AppLocker bloqueará los EXE/MSI firmados de WPS y AnyDesk con identidad reconocida. Primero prueba en auditoría. Paquetes Store y variantes distintas requieren validación de TI.");
            if(!DeviceInventory.IsAdministrator)return new("Por comprobar","Abre como administrador para comprobar el bloqueo AppLocker del equipo.");
            using var workspace=new SecureWorkspace();return await Execute("Read",workspace);
        }
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
        {return new("No comprobado",ErrorDetails.Message(ex));}
    }
    public async Task<PolicyState> ApplyAsync(bool audit,bool documents,bool access,SecureWorkspace workspace,bool compatibility)
    {
        RequireSupport();
        if(!DeviceInventory.IsAdministrator)throw new UnauthorizedAccessException("Abre como administrador para cambiar el bloqueo.");
        if(!documents||!access)throw new InvalidOperationException("Guarda los documentos de WPS y confirma acceso sin AnyDesk.");
        if(!audit)PolicyStatus.RequireAudit(await ReadAsync(),compatibility);
        return await Execute(audit?"Audit":"Enforce",workspace);
    }
    public async Task<PolicyState> RemoveAsync(SecureWorkspace workspace)
    {
        if(!DeviceInventory.IsAdministrator)throw new UnauthorizedAccessException("Abre como administrador para desactivar el bloqueo.");
        return await Execute("Remove",workspace);
    }

    private static async Task<PolicyState> Execute(string mode,SecureWorkspace workspace)
    {
        // ASVS 5.3.2 / 1.2.5: private, non-reparse files and separate process arguments; no shell interpolation.
        var folder=Path.Combine(workspace.SessionDirectory,"applocker-"+Guid.NewGuid().ToString("N"));SecureWorkspace.EnsurePrivateDirectory(folder,true);
        var script=Path.Combine(folder,"AppLockerHost.ps1");var audit=Path.Combine(folder,"audit.xml");var enforce=Path.Combine(folder,"enforce.xml");
        var doc=AppLockerPolicy.Create(true);AppLockerPolicy.Validate(doc);doc.Save(audit);AppLockerPolicy.Promote(doc).Save(enforce);
        using(var input=Assembly.GetExecutingAssembly().GetManifestResourceStream("Minseg.Core.AppLockerHost.ps1")!)
        using(var output=new FileStream(script,FileMode.CreateNew,FileAccess.Write))input.CopyTo(output);
        var ps=Path.Combine(Environment.SystemDirectory,@"WindowsPowerShell\v1.0\powershell.exe");
        var response=await ProcessRunner.RunAsync(new(ps,["-NoProfile","-NonInteractive","-File",script,"-Mode",mode,"-StoreRoot",workspace.Root,
            "-AuditXml",audit,"-EnforceXml",enforce]),TimeSpan.FromSeconds(60));
        if(response.TimedOut)throw new IOException("La operación de AppLocker sigue pendiente. No repitas el cambio todavía; comprueba el estado en unos momentos.");
        if(response.ExitCode!=0)throw new IOException("AppLocker no confirmó el cambio. "+(string.IsNullOrWhiteSpace(response.Error)?response.Output:response.Error)[..Math.Min(1800,(string.IsNullOrWhiteSpace(response.Error)?response.Output:response.Error).Length)]);
        var state=JsonSerializer.Deserialize<PolicyState>(response.Output.Trim())??throw new IOException("Windows no devolvió un estado válido.");
        workspace.Log(null,"AppLocker "+mode,"WPS y AnyDesk",state.Status,state.Detail);return state;
    }
}
