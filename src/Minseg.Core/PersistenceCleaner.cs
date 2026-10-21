using Microsoft.Win32;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
namespace Minseg.Core;

internal static class PersistenceCleaner
{
    public static void Clean(Finding finding,DeviceInfo device,SecureWorkspace workspace)
    {
        if(finding.Identity==null||SafetyRules.Identify(finding.Identity)!=finding.Product)throw new IOException("Identidad no comprobada.");
        bool absent=false;
        try{File.GetAttributes(finding.Identity.Path);}
        catch(Exception ex)when(ex is FileNotFoundException or DirectoryNotFoundException){absent=true;}
        if(!absent)
        {
            var current=new BinaryInspector().Read(finding.Identity.Path);
            if(current.Sha256!=finding.Identity.Sha256||SafetyRules.Identify(current)!=finding.Product)throw new IOException("El programa cambió. Analiza otra vez.");
        }
        switch(finding.Kind)
        {
            case FindingKind.Startup:CleanStartup(finding,device,workspace);break;
            case FindingKind.Task:CleanTask(finding,workspace);break;
            case FindingKind.Service:CleanService(finding,workspace);break;
            default:throw new IOException("No es un inicio automático compatible.");
        }
    }
    private static string Backup(SecureWorkspace workspace,string content,string extension)
    {
        var path=Path.Combine(workspace.BackupDirectory,Guid.NewGuid().ToString("N")+extension);
        using var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None);
        var data=System.Text.Encoding.UTF8.GetBytes(content);file.Write(data);file.Flush(true);return path;
    }
    private static void CleanStartup(Finding finding,DeviceInfo device,SecureWorkspace workspace)
    {
        var parts=ValidateStartupLocation(finding,device);
        var machine=parts[0]=="Machine";
        using var root=RegistryKey.OpenBaseKey(machine?RegistryHive.LocalMachine:RegistryHive.Users,RegistryView.Registry64);
        using var key=root.OpenSubKey(parts[1],true);if(key==null)return;
        var value=key.GetValue(parts[2],null,RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        if(value==null)return;
        if(PersistenceTarget.ContextDependent(value)||value!=finding.Reference||!string.Equals(PathSafety.ExecutableFromCommand(value),finding.Identity!.Path,StringComparison.OrdinalIgnoreCase))throw new IOException("El inicio automático cambió o requiere el contexto del usuario.");
        var backup=Backup(workspace,JsonSerializer.Serialize(new{Hive=parts[0],Key=parts[1],Name=parts[2],Value=value,Kind=key.GetValueKind(parts[2]).ToString()}),".startup.json");
        key.DeleteValue(parts[2],false);workspace.Log(finding.Product,"Limpiar inicio",finding.Name,"Limpiado","Respaldo: "+backup);
    }
    internal static string[] ValidateStartupLocation(Finding finding,DeviceInfo device)
    {
        var parts=finding.Location.Split('|');if(parts.Length!=3||parts[2]!=finding.Name)throw new IOException("Inicio no compatible.");
        var machine=parts[0]=="Machine";
        if((!machine&&parts[0]!="User")||parts[1]!=PersistenceLocation.RunKey(machine,device.UserSid))throw new IOException("Ruta de inicio no permitida.");
        return parts;
    }
    private static void CleanTask(Finding finding,SecureWorkspace workspace)
    {
        var type=Type.GetTypeFromProgID("Schedule.Service")??throw new IOException("No se pudo abrir el programador de tareas.");
        dynamic scheduler=Activator.CreateInstance(type)!;object? folderObject=null,taskObject=null,definitionObject=null,actionsObject=null,actionObject=null;
        try
        {
            scheduler.Connect();var slash=finding.Location.LastIndexOf('\\');
            if(slash<0)throw new IOException("Ruta de tarea no válida.");
            dynamic folder=folderObject=scheduler.GetFolder(slash==0?"\\":finding.Location[..slash]);
            dynamic task=taskObject=folder.GetTask(finding.Location[(slash+1)..]);
            dynamic definition=definitionObject=task.Definition;
            dynamic actions=actionsObject=definition.Actions;
            if(actions.Count!=1)throw new IOException("La tarea tiene varias acciones; se conserva.");
            dynamic action=actionObject=actions.Item(1);
            if(action.Type!=0||PersistenceTarget.ContextDependent((string)action.Path+" "+(string)action.Arguments)||!Environment.ExpandEnvironmentVariables((string)action.Path).Trim('"').Equals(finding.Identity!.Path,StringComparison.OrdinalIgnoreCase))throw new IOException("La tarea cambió o requiere otra cuenta.");
            if(task.State==4)throw new IOException("La tarea está funcionando. Espera a que termine; no se cerrará a la fuerza.");
            string xml=(string)task.Xml;
            if(PersistenceSnapshot.Hash(xml)!=finding.ContentHash)throw new IOException("La configuración de la tarea cambió. Se conserva; analiza otra vez.");
            var backup=Backup(workspace,xml,".task.xml");folder.DeleteTask((string)task.Name,0);
            workspace.Log(finding.Product,"Limpiar tarea",finding.Name,"Limpiada","Respaldo: "+backup);
        }
        finally{foreach(var obj in new[]{actionObject,actionsObject,definitionObject,taskObject,folderObject,(object)scheduler})if(obj!=null)Marshal.FinalReleaseComObject(obj);}
    }
    private static void CleanService(Finding finding,SecureWorkspace workspace)
    {
        if(!DeviceInventory.IsAdministrator)throw new UnauthorizedAccessException("Abre como administrador para limpiar este servicio.");
        var manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var service=OpenService(manager,finding.Name,0x00010000|1|4|0x20);
            if(service==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                QueryServiceConfig(service,IntPtr.Zero,0,out var needed);
                if(needed==0||needed>65536)throw new IOException("Configuración de servicio no válida.");
                var buffer=Marshal.AllocHGlobal((int)needed);
                try
                {
                    if(!QueryServiceConfig(service,buffer,needed,out _))throw new Win32Exception(Marshal.GetLastWin32Error());
                    var config=Marshal.PtrToStructure<ServiceConfig>(buffer);
                    var command=Marshal.PtrToStringUni(config.BinaryPath)??"";
                    if((config.Type&0x30)!=0x10||PersistenceTarget.ContextDependent(command)||!string.Equals(PathSafety.ExecutableFromCommand(command),finding.Identity!.Path,StringComparison.OrdinalIgnoreCase))
                        throw new IOException("Servicio compartido o cambiado: se conserva.");
                    using var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+finding.Name);
                    if(key==null)throw new IOException("No se pudo respaldar el servicio.");
                    var configuration=PersistenceSnapshot.Service(key);
                    if(PersistenceSnapshot.Hash(configuration)!=finding.ContentHash)throw new IOException("La configuración del servicio cambió. Se conserva; analiza otra vez.");
                    var backup=Backup(workspace,configuration,".service.json");
                    if(!QueryServiceStatus(service,out var status))throw new Win32Exception(Marshal.GetLastWin32Error());
                    if(status.State!=1)
                    {
                        if(!ControlService(service,1,out status))throw new IOException("El servicio no aceptó detenerse. Se conserva.");
                        var until=DateTime.UtcNow.AddSeconds(20);
                        while(status.State!=1&&DateTime.UtcNow<until){Thread.Sleep(250);if(!QueryServiceStatus(service,out status))throw new Win32Exception(Marshal.GetLastWin32Error());}
                        if(status.State!=1)throw new IOException("El servicio aún está cerrando. Se conserva hasta el próximo análisis.");
                    }
                    if(!DeleteService(service))throw new Win32Exception(Marshal.GetLastWin32Error());
                    workspace.Log(finding.Product,"Limpiar servicio",finding.Name,"Eliminación solicitada","Windows completará la eliminación al liberar sus referencias. Respaldo: "+backup);
                }
                finally{Marshal.FreeHGlobal(buffer);}
            }
            finally{CloseServiceHandle(service);}
        }
        finally{CloseServiceHandle(manager);}
    }
    [StructLayout(LayoutKind.Sequential)]private struct ServiceConfig{public uint Type,Start,Error;public IntPtr BinaryPath,LoadGroup;public uint Tag;public IntPtr Dependencies,Account,DisplayName;}
    [StructLayout(LayoutKind.Sequential)]private struct ServiceStatus{public uint Type,State,Controls,Win32Exit,SpecificExit,Checkpoint,WaitHint;}
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool QueryServiceConfig(IntPtr service,IntPtr config,uint size,out uint needed);
    [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool QueryServiceStatus(IntPtr service,out ServiceStatus status);
    [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool ControlService(IntPtr service,uint control,out ServiceStatus status);
    [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool DeleteService(IntPtr service);
    [DllImport("advapi32.dll")][return:MarshalAs(UnmanagedType.Bool)]private static extern bool CloseServiceHandle(IntPtr service);
}
