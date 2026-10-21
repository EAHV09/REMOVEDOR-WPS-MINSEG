using Microsoft.Win32;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text.Json;
namespace Minseg.Core;

// Uses Microsoft's documented default-associations policy; never edits UserChoice or its hash.
public static class OfficePolicy
{
    public static bool CanPrepare(string state)=>state is "Ready" or "Pending" or "GpoReady" or "GpoPending" or "Managed" or "Manual";
    public static bool CanSetPolicy(string state)=>state is "Ready" or "Pending";
    private const string PolicyKey=@"SOFTWARE\Policies\Microsoft\Windows\System", Value="DefaultAssociationsConfiguration";
    private const string OwnerKey=@"SOFTWARE\MINSEG-Control\OfficeDefaults";
    private static string Root=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"MINSEG-OfficeDefaults");
    public static string PreparedPath=>Path.Combine(Root,"Office-detectado.xml");
    private static RegistryKey Machine()=>RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64);
    internal static string State(bool domain,bool admin)
    {
        using var hive=Machine();using var policy=hive.OpenSubKey(PolicyKey);using var owner=hive.OpenSubKey(OwnerKey);
        using var mdm=hive.OpenSubKey(@"SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationDefaults");
        string? path=policy?.GetValue(Value) as string;
        bool managed=mdm!=null&&mdm.GetValueNames().Any(n=>n.StartsWith(Value,StringComparison.OrdinalIgnoreCase));
        return OfficeAutomation.PolicyState(domain,admin,path,managed,path!=null&&Owns(owner,path),
            string.Equals(path,PreparedPath,StringComparison.OrdinalIgnoreCase),PreparedIsOwned(owner));
    }
    private static bool Owns(RegistryKey? owner,string path)
    {
        if(string.Equals(path,PreparedPath,StringComparison.OrdinalIgnoreCase))return false; // A domain GPO owns this pointer.
        if(!SafetyRules.IsContained(Root,path))return false;
        try{return PathSafety.IsSafeExistingPath(path)&&SecureWorkspace.IsRestricted(Root)&&SecureWorkspace.IsRestricted(path)&&
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))==ReadPolicyState(owner).Find(path)?.Hash;}
        catch(IOException){return false;}
    }
    private static bool PreparedIsOwned(RegistryKey? owner)
    {
        try{return PathSafety.IsSafeExistingPath(PreparedPath)&&SecureWorkspace.IsRestricted(Root)&&SecureWorkspace.IsRestricted(PreparedPath)&&
            ReadPreparedState(owner).Accepts(OfficePreparedFile.Hash(PreparedPath));}
        catch(IOException){return false;}
    }
    private static OfficeFileState ReadPreparedState(RegistryKey? owner)=>ReadState<OfficeFileState>(owner,"PreparedState")??new(null,null);
    private static OfficePolicyState ReadPolicyState(RegistryKey? owner)=>ReadState<OfficePolicyState>(owner,"PolicyState")??
        new(owner?.GetValue("Path") is string path&&owner.GetValue("Sha256") is string hash?new(path,hash):null,null);
    private static T? ReadState<T>(RegistryKey? owner,string name)
    {
        if(owner?.GetValue(name) is not string value)return default;
        try{return JsonSerializer.Deserialize<T>(value)??throw new IOException("El estado de Office está incompleto.");}
        catch(JsonException ex){throw new IOException("El estado de Office no se pudo comprobar. Se conserva.",ex);}
    }
    private static void SaveState<T>(RegistryKey owner,string name,T state)
    {owner.SetValue(name,JsonSerializer.Serialize(state),RegistryValueKind.String);owner.Flush();}
    public static bool PreparedMatches(OfficePlan plan)
    {
        try
        {
            using var hive=Machine();using var owner=hive.OpenSubKey(OwnerKey);
            return plan.DetectionComplete&&plan.Associations.Count>0&&PreparedIsOwned(owner)&&File.ReadAllText(PreparedPath)==OfficeRecovery.Export(plan).ToString();
        }
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.Security.SecurityException){return false;}
    }
    private static void EnsureRoot()
    {
        PathSafety.RequireNoReparse(Path.GetDirectoryName(Root)!);
        var dir=new DirectoryInfo(Root);
        if(!dir.Exists)
        {
            var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);acl.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
            foreach(var sid in new[]{"S-1-5-18","S-1-5-32-544"})acl.AddAccessRule(new(new SecurityIdentifier(sid),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            acl.AddAccessRule(new(new SecurityIdentifier("S-1-5-11"),FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            dir.Create(acl);
        }
        PathSafety.RequireNoReparse(Root);if(!SecureWorkspace.IsRestricted(Root))throw new UnauthorizedAccessException("La carpeta de asociaciones tiene permisos inseguros.");
    }
    public static string Apply(DeviceInfo device,OfficePlan preview,SecureWorkspace journal)=>Prepare(device,preview,journal).Message;
    public static OfficePreparation Prepare(DeviceInfo device,OfficePlan preview,SecureWorkspace journal)
    {
        if(!DeviceInventory.IsAdministrator)throw new UnauthorizedAccessException("Se necesita administrador.");
        var fresh=OfficeRecovery.Read(device);
        OfficeAutomation.RequireComplete(fresh);
        string xml=OfficeRecovery.Export(fresh).ToString();
        if(xml!=OfficeRecovery.Export(preview).ToString())throw new InvalidOperationException("Office cambió desde la revisión. Vuelve a comprobarlo.");
        EnsureRoot();using var gate=new FileStream(Path.Combine(Root,"operacion.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
        if(State(fresh.DomainJoined,true)!=fresh.PolicyState)throw new InvalidOperationException("La política cambió. Se conserva.");
        using var hive=Machine();using var owner=hive.CreateSubKey(OwnerKey,true);
        var preparedHash=OfficePreparedFile.SaveRecoverable(PreparedPath,xml,ReadPreparedState(owner),state=>SaveState(owner,"PreparedState",state));
        journal.Log(null,"Preparar Office",PreparedPath,"Preparado",$"{fresh.Applications.Count} aplicaciones, {fresh.Associations.Count} formatos detectados en esta PC. SHA256 {preparedHash}");
        if(State(fresh.DomainJoined,true) is "Managed" or "Manual")
            return new(PreparedPath,false,"Configuración de esta PC preparada en "+PreparedPath+". "+OfficeRecovery.PolicyExplanation(fresh.PolicyState));
        var state=State(fresh.DomainJoined,true);
        if(state is "GpoReady" or "GpoPending")
        {
            journal.Log(null,"Office",PreparedPath,"Pendiente","XML propio actualizado; se conserva el enlace de la GPO. Windows lo procesa al iniciar sesión.");
            return new(PreparedPath,true,"Office detectado y preparado para la GPO de MINSEG. Windows lo aplicará al próximo inicio de sesión.");
        }
        if(!CanSetPolicy(state)||state!=fresh.PolicyState)throw new InvalidOperationException("La política cambió; se preparó el XML, pero no se modificó su configuración.");
        using var policy=hive.CreateSubKey(PolicyKey,true);
        var oldPath=policy.GetValue(Value) as string;var before=ReadPolicyState(owner);
        if(oldPath!=null&&!Owns(owner,oldPath))throw new InvalidOperationException("Ya existe otra política. Se conserva.");
        if(oldPath!=null&&File.ReadAllText(oldPath)==xml)
            return new(oldPath,true,"La configuración de Office ya está programada y coincide con lo instalado. Se comprueba de nuevo al iniciar sesión.");
        var path=Path.Combine(Root,Guid.NewGuid().ToString("N")+".xml");
        var hash=OfficePreparedFile.Save(path,xml,null);
        if(!Equals(policy.GetValue(Value),oldPath)||State(fresh.DomainJoined,true)!=fresh.PolicyState)throw new InvalidOperationException("La política cambió. Se conserva.");
        journal.Log(null,"Office",path,"Preparado",$"{fresh.Associations.Count} formatos. Política anterior: {oldPath??"ausente"}; XML anterior conservado. SHA256 {hash}");
        OfficePolicyState.Publish(before,new(path,hash),oldPath,()=>policy.GetValue(Value) as string,
            next=>{policy.SetValue(Value,next,RegistryValueKind.String);policy.Flush();},state=>SaveState(owner,"PolicyState",state));
        journal.Log(null,"Office",path,"Pendiente","Windows aplicará las asociaciones al iniciar sesión. No se cerró la sesión.");
        return new(path,true,"Office detectado y programado para el próximo inicio de sesión. Los predeterminados actuales todavía deben comprobarse.");
    }
    public static void Remove(SecureWorkspace journal)
    {
        if(!DeviceInventory.IsAdministrator)throw new UnauthorizedAccessException("Se necesita administrador.");
        EnsureRoot();using var gate=new FileStream(Path.Combine(Root,"operacion.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
        using var hive=Machine();using var policy=hive.OpenSubKey(PolicyKey,true);using var owner=hive.OpenSubKey(OwnerKey,true);
        string? path=policy?.GetValue(Value) as string;
        if(path==null||!Owns(owner,path))throw new InvalidOperationException("No hay una política propia e intacta que se pueda desactivar.");
        policy!.DeleteValue(Value);owner!.DeleteValue("Path",false);owner.DeleteValue("Sha256",false);owner.DeleteValue("PolicyState",false);
        journal.Log(null,"Office",path,"Política desactivada","No se restauran elecciones antiguas del usuario ni se cambia la política de TI. XML conservado.");
    }
}
