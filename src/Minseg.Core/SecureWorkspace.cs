using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
namespace Minseg.Core;

public sealed class SecureWorkspace:IDisposable
{
    public string Root{get;}
    public string SessionDirectory{get;}
    public string BackupDirectory{get;}
    private readonly FileStream journal;
    public List<OperationEntry> Entries{get;}=[];
    public RemovalSession RemovalSession{get;}=new();
    public SecureWorkspace()
    {
        var parent=Environment.GetFolderPath(DeviceInventory.IsAdministrator?Environment.SpecialFolder.CommonApplicationData:Environment.SpecialFolder.LocalApplicationData);
        Root=Path.Combine(parent,"MINSEG-Control");
        EnsurePrivateDirectory(Root,DeviceInventory.IsAdministrator);
        SessionDirectory=Path.Combine(Root,DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N")[..8]);
        EnsurePrivateDirectory(SessionDirectory,DeviceInventory.IsAdministrator);
        BackupDirectory=Path.Combine(SessionDirectory,"respaldo");EnsurePrivateDirectory(BackupDirectory,DeviceInventory.IsAdministrator);
        journal=new FileStream(Path.Combine(SessionDirectory,"acciones.jsonl"),FileMode.CreateNew,FileAccess.Write,FileShare.Read);
    }
    public void Log(Product? product,string action,string target,string status,string detail)
    {
        var entry=new OperationEntry(DateTimeOffset.Now,product?.Display()??"Equipo",action,target,status,detail);
        // ASVS 16.4.1 / 16.4.2: JSON encoding, restricted ACL and exclusive writer.
        var bytes=JsonSerializer.SerializeToUtf8Bytes(entry);journal.Write(bytes);journal.WriteByte(10);journal.Flush(true);Entries.Add(entry);
    }
    public static void EnsurePrivateDirectory(string path,bool admin)
    {
        var parent=Path.GetDirectoryName(path)!;PathSafety.RequireNoReparse(parent);
        var security=new DirectorySecurity();security.SetAccessRuleProtection(true,false);
        var ids=new List<SecurityIdentifier>{new(WellKnownSidType.LocalSystemSid,null),new(WellKnownSidType.BuiltinAdministratorsSid,null)};
        if(!admin) ids.Add(WindowsIdentity.GetCurrent().User!);
        security.SetOwner(ids[admin?1:2]);
        foreach(var id in ids)security.AddAccessRule(new FileSystemAccessRule(id,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        var directory=new DirectoryInfo(path);
        if(!directory.Exists) directory.Create(security);
        PathSafety.RequireNoReparse(path);
        if(!IsRestricted(path,ids.Select(id=>id.Value).ToHashSet())) throw new UnauthorizedAccessException("La carpeta de trabajo tiene permisos inseguros. Usa una carpeta MINSEG-Control protegida.");
    }
    public static bool IsRestricted(string path,HashSet<string>? permitted=null)
    {
        permitted??=new HashSet<string>{"S-1-5-18","S-1-5-32-544","S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"};
        try
        {
            FileSystemSecurity acl=Directory.Exists(path)?new DirectoryInfo(path).GetAccessControl():new FileInfo(path).GetAccessControl();
            var owner=(SecurityIdentifier)acl.GetOwner(typeof(SecurityIdentifier))!;
            if(!permitted.Contains(owner.Value))return false;
            const FileSystemRights modify=FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership|FileSystemRights.DeleteSubdirectoriesAndFiles;
            foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
                if(rule.AccessControlType==AccessControlType.Allow&&(rule.PropagationFlags&PropagationFlags.InheritOnly)==0
                    && (rule.FileSystemRights&modify)!=0&&!permitted.Contains(rule.IdentityReference.Value))return false;
            return true;
        }
        catch(UnauthorizedAccessException){return false;}
    }
    public void Dispose()=>journal.Dispose();
}
