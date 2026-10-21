using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
namespace Minseg.Core;

public static class OfficeRecovery
{
    public static bool RequiresUserChoice(OfficePlan plan)=>plan.PolicyState=="Manual"&&plan.CanVerifyUser&&plan.Associations.Count>0&&plan.Matched<plan.Associations.Count;
    public static OfficePlan Read(DeviceInfo device)
    {
        var warnings=new List<string>();var candidates=new List<OfficeAssociation>();bool complete=true;
        var signatures=new Dictionary<string,BinaryIdentity?>(StringComparer.OrdinalIgnoreCase);
        var versions=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        var current=new Dictionary<string,(string? ProgId,string? Executable,bool Exists)>(StringComparer.OrdinalIgnoreCase);
        bool sameUser=device.Operator.Equals(device.User,StringComparison.OrdinalIgnoreCase);
        foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32})
        {
            try
            {
                using var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,view);
                using var classes=machine.OpenSubKey(@"Software\Classes");
                using var registered=machine.OpenSubKey(@"Software\RegisteredApplications");
                if(classes==null||registered==null)continue;
                foreach(var registration in registered.GetValueNames())
                {
                    var location=registered.GetValue(registration) as string;
                    if(string.IsNullOrEmpty(location)||!location.StartsWith("Software\\",StringComparison.OrdinalIgnoreCase))continue;
                    using var capability=machine.OpenSubKey(location);if(capability==null)continue;
                    foreach(var kind in new[]{"FileAssociations","URLAssociations"})
                    {
                        using var associations=capability.OpenSubKey(kind);if(associations==null)continue;
                        foreach(var identifier in associations.GetValueNames())
                        {
                            if(!OfficeAssociationRules.Apps.Values.Any(a=>a.Extensions.Contains(identifier,StringComparer.OrdinalIgnoreCase)))continue;
                            var progId=associations.GetValue(identifier) as string;if(string.IsNullOrEmpty(progId))continue;
                            using var command=classes.OpenSubKey(progId+@"\shell\open\command");
                            var commandText=command?.GetValue("") as string??"";
                            var exe=PathSafety.ExecutableFromCommand(commandText);
                            if(exe==null||!OfficeAssociationRules.Allowed(identifier,exe))
                            {
                                if(OfficeDiscovery.IsOfficeProgId(progId))
                                {complete=false;warnings.Add(identifier+": registro de Office incompleto o destino no compatible; revisa la instalación de Office.");}
                                continue;
                            }
                            if(!signatures.TryGetValue(exe,out var identity))
                            {
                                try
                                {
                                    identity=new BinaryInspector().Read(exe,false);
                                    versions[exe]=System.Diagnostics.FileVersionInfo.GetVersionInfo(exe).FileVersion??"No disponible";
                                }
                                catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or System.Security.Cryptography.CryptographicException){warnings.Add("No se pudo verificar "+Path.GetFileName(exe));}
                                signatures[exe]=identity;
                            }
                            var candidate=OfficeDiscovery.Registered(registration,identifier,progId,commandText,identity,versions.GetValueOrDefault(exe,"No disponible"));
                            if(candidate==null)
                            {complete=false;warnings.Add(OfficeAssociationRules.Apps[Path.GetFileName(exe)].Name+": no se pudo verificar el programa; no se activa la configuración automática.");continue;}
                            // Only registered ProgIDs pointing directly to signed Office desktop binaries are proposed.
                            if(!current.TryGetValue(identifier,out var target))
                            {
                                var opening=sameUser?QueryAssociation(identifier,2,"open"):null;
                                target=(sameUser?Current(identifier):null,opening,opening!=null&&SafetyRules.IsLocalPath(opening)&&File.Exists(opening));current[identifier]=target;
                            }
                            candidates.Add(candidate with{CurrentProgId=target.ProgId,CurrentExecutable=target.Executable,CurrentExecutableExists=target.Exists});
                        }
                    }
                }
            }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException){complete=false;warnings.Add("No se pudo leer Office en "+view+".");}
        }
        var selected=OfficeDiscovery.Select(candidates,warnings,out var unambiguous);complete&=unambiguous;
        bool domain=false;string state;
        try{domain=IsDomainJoined();state=OfficePolicy.State(domain,device.Administrator);}
        catch(Exception){state="Unknown";warnings.Add("No se pudo comprobar la administración de este equipo.");}
        warnings.Add("Solo se incluyen formatos registrados de aplicaciones Office de escritorio verificadas. Office web y aplicaciones empaquetadas requieren la configuración de Windows.");
        return new(selected,warnings.Distinct().ToArray(),domain,sameUser,state){DetectionComplete=complete};
    }
    public static XDocument Export(OfficePlan plan)=>OfficeAssociationRules.Xml(plan.Associations);
    public static string Explain(OfficePlan plan)=>plan.DetectionSummary+"\n"+plan.Summary+"\n\n"+string.Join("\n",plan.Associations.Select(a=>$"{a.Identifier} → {a.Application}: {(plan.CanVerifyUser?a.Status:"Usa el usuario conectado")}\n  Versión detectada: {a.DetectedVersion}\n  Apertura actual: {a.OpeningTarget}"))+"\n\n"+PolicyExplanation(plan.PolicyState)+"\n\n"+string.Join("\n",plan.Warnings);
    public static string PolicyExplanation(string mode)=>mode switch
    {
        "Ready"=>"Se puede programar Office por defecto para todos los usuarios en el próximo inicio de sesión. No se cerrará la sesión ahora.",
        "Pending"=>"Política de Office programada. Windows la procesa al iniciar sesión; el resultado actual se comprueba por separado.",
        "GpoReady"=>"La GPO de MINSEG está lista. Prepara el XML de Office de esta PC para que Windows lo aplique al iniciar sesión.",
        "GpoPending"=>"Office preparado para la GPO de MINSEG. Puedes actualizarlo si cambias Office. Se aplica al próximo inicio de sesión.",
        "Administrator"=>"Abre como administrador para programar las asociaciones de Office al próximo inicio de sesión.",
        "Managed"=>"TI ya administra los predeterminados. El botón prepara el XML propio de esta PC para integrarlo en su política. La política actual se conserva.",
        "Manual"=>"Falta tu elección en Windows para los formatos pendientes. Configura cada aplicación de Office de la lista; al volver comprobamos el resultado.",
        _=>"No se pudo comprobar la política de predeterminados. No se aplicarán cambios."
    };
    public static string? Current(string identifier)=>QueryAssociation(identifier,20,null);
    private static string? QueryAssociation(string identifier,uint query,string? verb)
    {
        uint length=32768;var text=new StringBuilder((int)length);
        return AssocQueryString(identifier.StartsWith('.')?0u:0x1000u,query,identifier,verb,text,ref length)==0?text.ToString():null;
    }
    public static string SettingsUri(string? registration)
    {
        var version=Environment.OSVersion.Version;
        try
        {
            using var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64);
            using var key=machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if(key?.GetValue("UBR") is int revision&&revision>=0)version=new(version.Major,version.Minor,version.Build,revision);
        }
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException){return "ms-settings:defaultapps";}
        return OfficeDefaultsGuide.SettingsUri(registration,version);
    }
    internal static bool IsDomainJoined()
    {
        var status=NetGetJoinInformation(null,out var buffer,out var join);
        try{if(status!=0)throw new IOException("No se pudo consultar el dominio.");return join==3;}
        finally{if(buffer!=IntPtr.Zero)NetApiBufferFree(buffer);}
    }
    [DllImport("shlwapi.dll",CharSet=CharSet.Unicode)]private static extern uint AssocQueryString(uint flags,uint query,string association,string? extra,StringBuilder output,ref uint length);
    [DllImport("netapi32.dll",CharSet=CharSet.Unicode)]private static extern int NetGetJoinInformation(string? server,out IntPtr name,out int status);
    [DllImport("netapi32.dll")]private static extern int NetApiBufferFree(IntPtr buffer);
}
